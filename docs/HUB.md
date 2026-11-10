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
history) and **S14** (blame and file history, §13.22) are built too, recorded in
`docs/design/server/phase-3-server-history.md` §10, §11 and §12. Statements about what Veil does today cite the
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
| Requests per device / per address | 200 / s burst, 50,000 / h a device (one person's agents share it until S11); 20 / s, 1,000 / h an address without a session (`--device-rate`, `--anonymous-rate`; §13.25, BUG-1339) | abuse |
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
| `POST …/objects` | upload object frames, plain or encoded (§13.15): decoded (bounded), re-hashed, canonically decoded, format-checked, compressed when that is smaller, and **staged** as one pack (S28, §13.20): nobody's until a push of the same person lists it, deleted if the push refuses it. Answers a **receipt** per object (a server MAC over project ‖ person ‖ id ‖ pack, then the pack's name) |
| `POST …/push {updates: [{branch, expected, new}], force, receipts}` | complete and check every new snapshot, then move the branches in **one serialisable transaction of compare-and-swaps** (`UPDATE branches SET target = new WHERE … AND target = expected`); one lost race rejects the whole push with 409 and `vl` retries |
| `POST …/changes {base, edits, onto?, change_id?, receipts}` | a commit through the API, without a checkout (S10, §13.13) |
| `POST …/land {onto, snapshot \| base+edits, receipts, wait}`, `GET …/land/{ticket}` | submit a landing to the landing service, and its outcome (S17, §13.19) |
| `GET …/access?path=` | the deciding line and who it names; only for a path the caller may read |
| `…/groups`, `GET|POST …/rings/{scope}`, `GET /v1/people/{name}/devices` | groups; key rings of secret scopes; a person's devices (active, the newest pending, removed), the vouches and invite joins the server stores, which devices check before sharing a key (§13.11, §13.12) |
| `POST /v1/devices/vouch {device, signature}` | the signed-in device vouches for another device of its person; a pending one becomes active |
| `GET /v1/people/{me}/pending/{fingerprint}` | one of the caller's own pending devices, by fingerprint; if none waits, the fingerprint is kept for the person for an hour, so the bound on pending devices never pushes that device out (§13.12) |
| `POST /v1/devices/remove {device, project?}` | remove a device: its person, from another device, everywhere (its sessions end); or an admin of `project` where the person takes part, from that project only (§13.12, BUG-843) |
| `POST …/invites {key, person, group, expires_at}`, `POST …/invites/join {key, device, signature}` | an admin records an invite's public key; the signed-in device joins under it, once, before it expires (§13.12) |
| `GET …/keys/pending` | the people whose devices may wait for keys, with their devices, vouches, joins and removed devices: a hint for the devices that share keys (§13.12) |
| `GET …/q/log`, `…/q/show`, `…/q/tree`, `…/q/file`, `…/q/diff`, `POST …/q/ancestry` | history answered by the server, on the caller's projected history only (S13: `docs/design/server/phase-3-server-history.md` §11) |
| `GET …/q/blame`, `…/q/history` | who introduced each line of a file, and the changes that made each of its versions (with `follow`, across renames between paths the caller reads), on the caller's projected history only (S14: §13.22) |

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
* **Objects first, then the branch move:** the push's packs are written
  before its transaction and listed in it (S28, §13.20), so a crash leaves
  only packs no transaction listed, which no read finds.

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

### 13.19 S17: the landing service (as built)

Milestone S17 (`docs/design/server/phase-4-agent-scale.md` §4.1–4.6, §8).
Code: `crates/veil-server/src/landing/` (`mod.rs`: submit, waiters, the
services a server runs; `service.rs`: one branch's service; `edits.rs`:
edit sets, the fast path, the landing check; `rules.rs`: `.veilrules`),
`migrations/0011_landing.sql`, `vl land` (`crates/vl/src/hub.rs`,
`hub_cmd.rs`), the messages in `veil_core::hub::land`.

```text
POST /v1/projects/{p}/land
{ "onto": "main",
  "snapshot": "<id, as a push names it>"            // uploaded first, with receipts
  | "base": "<id as the caller sees it>", "edits": [...], "description", "change_id"?,
  "receipts": {...}, "wait": true }
→ { "ticket", "state": "queued" | "landed" | "conflict" | "rejected",
    "change_id"?, "landed": ["<each change's snapshot, as the caller sees it>"],
    "message"?, "paths": ["<the change's own paths that moved>"], "warnings": [...] }
GET /v1/projects/{p}/land/{ticket}[?wait=false]     // its submitter's only; anyone else: 404
```

**Submitting** (one request, one database commit). The change is built and
checked by the code a push or an API commit runs, never a copy of it: an
uploaded snapshot goes through `sync::push` (signatures, `sync::complete`:
the graft, write access, access lines and `.veilrules` changed only by
admins, closure, personal keys, secrets as ciphertext, check 9), and edits
through `changes::create` (the same `complete`, inline text held in memory
until the checks pass). Instead of a branch's compare-and-swap, the
request's transaction inserts one **queue row**: the stack (oldest first,
at most 64 changes), the submitter, the access epochs its checks ran under,
and the branch's **lineage** its stack was judged under (below).

**The stack is the submitter's own history** (`landing::stack`, for every
route: a pushed or uploaded snapshot, and edits on a `base`; S17 cycle 3,
simplified after its review). **A submitter lands only the changes they
see whole** (`docs/VISIBILITY.md`: a change they cannot see does not exist
for them):

* The submitted snapshot's real first-parent line is read down to the first
  snapshot on the branch (below). Of the changes held there (another
  branch's, an API commit, a landing answered `conflict`), one whose own
  edits (against its first parent) are all at paths the submitter can read
  is theirs to land; one hidden from them, or seen only in part, is left
  unlanded for someone who sees it whole (its author, an admin), and is not
  in the stack. A held change with unresolved conflicts the submitter can
  see is refused (naming no path); one they cannot see does not count.
* **Each change lands as its own edits**: its diff against its first parent
  (a merge with a parent on the branch, which ends the stack: against that
  parent, BUG-1271). As every change landed is seen whole, that real diff is
  exactly what the submitter saw of it. Its **base** in the stack is the
  change below it that lands, or where the line stops: a merge lands only on
  the tip it was made on as the submitter sees it.
* Every change lands as a new snapshot on the tip, signed by the server,
  predecessor the submitted one, never the submitted snapshot itself (a
  merge keeps its other parents). So changes hidden from the submitter
  below or between theirs never change an answer: its state, the paths a
  conflict names (the change's own, all readable by the submitter), and the
  snapshots it lists (as the submitter sees them) are those of the same
  changes with nothing hidden there. **What an answer does tell** (BUG-1406,
  decided: `docs/VISIBILITY.md`): whether a change the submitter sees also
  touched folders they cannot see, as it is left for someone who sees it
  whole (it is not in what lands, "nothing to land … or holds edits you
  cannot see"); never which folders, which paths, how many, or what.
* **The line is read change by change, as the submitter sees it**
  (`landing::stack`): a held change on the branch ends it, as soon as it is
  met; a change whose edits are on the branch already is skipped, and the
  line read on below it (what is below it may not be: a change left out by
  someone who could not see it, BUG-1311); a run of changes hidden from
  the submitter is stepped over in one step (their projection of the first
  one; of that view's memos with that projection, the one that did not
  collapse into its parent's: one row of a partial index, however long the
  run, BUG-1468), counting toward nothing (BUG-1409).
* **"Already landed" is asked by change id and author, of changes the
  submitter sees whole** (BUG-1408, BUG-1465, BUG-1466, BUG-1522, BUG-1526,
  BUG-1527, BUG-1547, BUG-1548, BUG-1579, BUG-1580; one seen in part is left
  out, never judged by edits they cannot see): a `landings` row is a fast
  path whose absence means nothing; the question is the branch's record of
  its changes in its lineage (`landed_changes`, keyed by `(project, branch,
  lineage, change_id, author)` and indexed by `(project, branch, change_id,
  author)`: one row per change and author landed there, written by every
  route that moves a branch, the landing service, a push of new snapshots
  and an API commit `onto`; one lookup no bound limits), the landed
  revision then asked of the bounded ancestry below (yes, no, or `warming`;
  never "no" from a truncated search). The author is the person whose
  signature is on the change, and on the landed revision (its device key,
  its `origins` row, or its `change_refs` creator); **no predecessor list is
  read at all**, and a row with the same change id by another author is
  ignored completely. A rebase or rewrite keeps the change id and author,
  not the snapshot: a revision whose edits are all the landed revision's
  (the same change, or one rebased on a tip that holds it) is skipped; one
  that brings further edits is refused ("this change already landed … with
  other edits: make a new change for the further edits"), never applied
  again. Every answer, including "nothing to land", names every change left
  out as landed already ("change … already landed on … with the same edits:
  not landed again", BUG-1549): never silent.
* At most 64 changes the submitter sees land, counted as they are found;
  at most 4,096 they see are read, then `warming`; changes they cannot see
  count toward neither.

**"On the branch" is the branch's real ancestry**, with a **lineage guard**
(BUG-1300): `branches.lineage` is a new value (a sequence) at every
creation, every forced update and every deletion (a branch made again
starts a new lineage); fast-forward pushes, API commits and the service
keep it. `landings` and `landed_changes` rows carry the lineage they were
made under, and only rows of the branch's current lineage count; a queue row
lands only under the lineage its stack was judged under (else it is
`rejected`: "the branch was reset since this change was submitted: submit it
again"); the service's compare-and-swap is on tip and lineage. Stale rows
can never make a change count as landed.

**Is a snapshot on the branch** (`landing::Ancestry`, one per submit),
cheapest first: the tip itself; `landings` of the current lineage (an
agent's base is its own last landing, or a tip it read; batches record the
tip they move from); the derived commit graph when it holds the tip (its
jump table, bounded by generation), never waiting for the deriver; else a
walk down from the tip shared by the whole stack: while the line is read,
at most 256 snapshots (a base a few landings below a tip the deriver has
not reached yet: BUG-1405), and once it is read, for what was left
undecided, at most 4,096, whose frontier the derived graph then answers
for. Past that, `warming` (503: try again).

**What a submit costs at most, whatever the hidden history**: one
statement for the branch, and for each change the submitter sees on the
line (at most 4,096): a `landings` lookup, a graph lookup or the shared
walk (at most 4,096 snapshots a submit in all), their projection and one
row of `projections_own` for the run below it, one `landed_changes` lookup
by `(project, branch, lineage, change_id, author)` (asked of the same
bounded ancestry), and one diff of its own edits. A hidden run costs one
row, however long; when its memos do not say which change it stands for
(memos older than the column, or two changes alike for the view), the run is
read and diffed, at most 4,096 changes, then `warming` (the deriver is asked
to catch up). An agent's landing on its own last one costs the branch's row
and one `landings` lookup.

**Which real snapshot a projected id names** (BUG-1314, BUG-1407,
BUG-1467, BUG-1520, BUG-1521): several changes hidden from a viewer can
share one projection. **One resolution for every route** (`sync::resolve_for`:
an API commit's `base`, a push's parents, a landing's), each answer checked
to project to the name for its caller: the tip of the branch the change
goes to (a push's branches, an API commit's `onto` or the landing's
branch), then the default branch's, that they see as the name (also when
the name is a snapshot they see whole under a change hidden from them at
the tip, BUG-1525); else committed history named by its own id, if they see
it so; else, of their own view's
real snapshots with that projection (never another view's, never by when a
memo was stored), the newest when they are one line, and when lines
diverge (two branches' hidden work on one change they see) or there are
more than 4,096, the change they all stand on (the one memo that did not
collapse: `projections_own`), which carries no line's hidden work (with no
such one change, two alike for them on two lines: a landing takes the
lowest id of their ends, its edits the same on the tip; anything that moves
a branch to it is refused); else their own change's latest revision (a
name from before an access change).
No bound answers `warming` for ever. A push names as new only what its
pusher uploaded (their receipts): any other name it cannot resolve is
"snapshot … was not uploaded", the same for a snapshot that does not exist
and one they cannot see (BUG-1523). A landing of edits takes the server's
memory of the caller's view first, checked the same way.

The snapshots become committed history in the submit's commit (they
resolve and project like any other). With `wait` (the default) the request
answers once the outcome is known, up to 30 s, else at `queued`.

**The landing service.** One per branch, on whichever server holds the
branch's **lease** (`landing_leases`: a holder, a fencing epoch bumped at
every takeover, an expiry on the database's clock, 2 s unless renewed). A
submit wakes the service on its own server, starting one if no other
server holds the lease; a waiting submitter hears from the service on its
server as soon as the batch commits; one poller per branch and server
answers the others from the rows of the branch finished since it last
looked (every 250 ms while another server holds the lease, every 5 s as a
fallback while this one does: a cost that follows the landings, never the
number of waiters), and keeps a service running; a starting server resumes
every branch with queued rows. A service with nothing to do
for 5 s gives the lease back. Its loop:

* **Batch:** every ready row not in the batch being committed, in queue
  order (the database's clock at submit), at most 64 (larger batches cost
  more per landing here: `LOAD.md`); no entry joins a batch that made
  8 MiB of new objects with the batch being committed (`BATCH_BYTES`), and
  the build stores what it holds as soon as it passes that, so no entry and
  no batch, its first entry included, holds more. An entry whose edits touch `.veilpolicy` or
  `.veilrules` ends the batch before it and **lands alone**; nothing is
  built after it until it is committed.
* **For each change of an entry's stack:** landed already by another
  stack (`landings` of the current lineage, or this batch), it is skipped.
  Otherwise **the fast path**: every path of its edits (above) must be, on the tip, what it was in its base: the same
  entry (kind, content, mode, label), absent in both, or under the same
  non-folder in both. Exact per path: nothing else on the tip matters. Then
  its edits are applied (only the folder listings on the way are rewritten;
  folders are made where needed and dropped once empty) and a **new
  snapshot** is signed by the server: parent the tip (a merge: and its other
  parents), the change's id, description, author and time, predecessor the
  submitted snapshot. A merge lands only on the tip it was made on, and the
  push's checks run again on it (every parent). A path that moved:
  **`conflict`**, naming the change's own paths that moved (never landed
  over; content merges are S18). A stack lands all or nothing.
* **The landing check:** each new snapshot's diff against its parent must be
  exactly the change's edit set, path for path; a mismatch rejects the
  entry (and logs a bug, with ids only), never lands it.
* **Checks again when what they read changed:** while the submitter's and
  the project's access epochs (§13.14) are those the submit recorded, and
  the tip's `.veilpolicy` is the base's, the submit's checks still hold.
  Otherwise (someone removed from a group, a device barred, an access
  change landed, a policy file moved) the push's checks run again on the
  new parents (every real parent of a merge), as the submitter is now:
  their projection of the new snapshot is grafted back by `sync::complete`
  and must give exactly its tree. When access changed, write access to
  each path is decided **before** the fast path reads the tip: someone who
  may no longer write a path is `rejected`, never told whether it changed.
  Someone no longer in the project is refused. A change of who has access
  on the default branch is accepted in the batch's transaction (an admin's
  only), which bumps the project's epoch: every later entry is checked
  against it. **The branch rules** are judged the same way: a landing on
  the default branch that changes `.veilrules` against its tip is an
  admin's only (so is a push or an API commit that moves it), never "the
  same as one of its parents'".
* **Projections per viewer, never a walk:** the service keeps every view
  key of the project's people and of anyone on Earth (at most 64; re-read
  when the project's access epoch changes) with its projection of the tip,
  and projects each new snapshot onto it (`sync::project_one`, from stored
  memos only). A key it does not keep is attached from its newest memo on
  the branch's recent first-parent line (the last 1,024 snapshots it knows;
  S12's deriver keeps tips memoised for every key), projecting only what
  came after, within 256 projections a batch (`ATTACH_BUDGET`); a key with
  no memo there, or past the budget, is handed to S13's background fill
  (`query::graph::prefill`). Each projection is held as soon as it is made
  (the next one reads it). Every projection made is stored in the batch's
  commit, and a stored memo wins: one written meanwhile with another value
  rolls the batch back (it is built again). Outcomes hold real snapshots;
  each answer is projected for its asker (from the memo, else in their own
  request, as a pull would).
* **Pipelined:** while batch *n* is stored and committed, batch *n+1* is
  built on the tip *n* leaves. If *n* loses (the branch moved under it: an
  admin's forced push; or the lease was lost), *n+1* is discarded and built
  again from the database.
* **One commit per batch:** the new objects are stored first, then one
  transaction: the lease (its holder and epoch: **fencing**), the branch's
  compare-and-swap, an accepted policy, the queue rows (each must still be
  `queued`, else nothing commits: an entry never lands twice), the
  snapshot, `landings` and memo rows, an audit row and the tips notice.
  A batch that lands nothing still compares the tip and lineage it judged
  on (BUG-1304): if the branch moved by another route, its entries are built
  again on the database's tip.
* **Retention, also while busy** (BUG-1303): every 5 s the service deletes
  finished queue rows and `landings` rows older than an hour (each by an
  index on its project and time, so a pass with nothing to delete reads
  nothing), at most 20,000 of each a pass (4,000 a second, four times what 1,000 landings a
  second add). At 1,000 landings a second a branch's tables hold about
  3.6 million rows each in steady state (an hour); a ticket's outcome is
  readable for that hour, and a base older than it is found by the graph or
  the walk above.

**Protected branches.** `.veilrules` at the project root (TOML;
`[branches.NAME] protected = true`; other tables are left to later
milestones, an unknown key under a branch is refused). Only admins change
it, on any branch (`sync::complete`), and an admin's must parse, so the
default branch's current file is always an admin's. A protected branch is
moved only by its landing service: a push of it **lands instead** (its new
snapshots, as one stack, need not be on the tip; `vl push` waits and
reports `landed`); a commit through the API with `onto` it is kept but
`rejected`; deleting it needs an admin's `--force`; an admin's
`vl push --force` still moves it (audited). Product decision 9 (protected
`main` by default for new projects) is not applied yet: protection is
opt-in.

**`vl land [REV] [--onto BRANCH] [--no-wait] [--status TICKET]`** uploads
REV (default `@-`) and what the server lacks under it, submits it, and on
`landed` pulls and moves the local tag of the branch to where the change
landed if it was at REV or below. The working copy stays on REV, a
predecessor of the landed snapshot with the same content at every path it
edits; the next change made on it lands the same way.

**Measured** (`docs/design/scale/LOAD.md`, "The landing service", after the
cycle-3 redesign): into one `main`, **993 landings/s with 1,000 agents at a
1,000/s target, p50 79 ms and p99 327 ms**, 1.14 database commits, about 16
statements and 14 storage writes per landing; **943/s with 10,000 agents,
p50 270 ms, p99 1.01 s**; 1,208/s at most. No collisions. (Re-measured after the
redesign's reviews on a machine that was never quiet: the same cost per
landing, the latencies of a loaded object store; `LOAD.md`.) The object
store's synced writes are the limit (packs, S28).

**Limits.** When S21 merges, its `prs::state::record_landing` joins the batch's transaction (right after the branch's compare-and-swap) for every move of the default branch, so the review rules in force never lag a landing, and landing onto a protected branch meets S21's review rules by every route (S21's follow-up wires both). Fair share between people and sessions is FIFO here (S24); a
submitter whose view key no service keeps (a new one after an access
change) waits, in their own request, for their view's first projection;
the batch-tip memos for other viewers are S12's.

Threat review (phase 4 §6, rows 1–4, and what S17 adds), tests in
`server_hub` `landing` and `veil-server` `landing::edits`:

| # | Attacker | Capability | Harm | Mitigation | Test |
|---|---|---|---|---|---|
| 1 | An agent with access to `src/` only | submits edits touching `billing/`, the root, `.veilrules`, a secret in a file | writes where it may not | the push's checks at submit (nothing is queued); again at landing when access changed | `access_is_checked_at_submit_and_again_when_an_entry_lands` |
| 2 | An admin and an agent at once | a revoking policy change queued between two writes of the revoked path | the second lands under rules that no longer allow it | policy and rules changes land alone; the epoch they bump re-runs later entries' checks; no batch is built before they commit | same: the second write is `rejected` |
| 3 | — (failover) | two servers both run a branch's service | `main` moved twice from one tip, a lost or doubled change | the lease's epoch checked in the batch's transaction; queue rows must still be `queued`; the branch's compare-and-swap | `only_the_lease_holder_lands_and_every_ticket_lands_once_across_servers` (two servers, the lease stolen every 30 ms: every change on `main` exactly once) |
| 4 | — (a bug) | the fast path rewrites a tree wrongly | a change lost or altered | the landing check before the commit; property test against applying each change's edits by hand | `batched_landings_equal_sequential_edits`, `non_overlapping_changes_land_in_batches_each_once_with_exactly_its_edits` |
| 5 | A submitter | reads a conflict or a ticket | learns about hidden folders | a conflict names only the change's own paths; tickets are random and their submitter's only (404 for anyone else) | `hostile_landing_requests_are_refused` |
| 6 | Any participant | a stale clone pushes a protected `main` | moves it over others' work | a push of a protected branch lands instead (fast path or `conflict`) | `protected_branches_move_only_by_landing_and_push_lands_instead` |
| 7 | A non-admin, even one given `.veilrules` | unprotects `main` | bypasses the landing service | `.veilrules` changes are admins' only, on any branch | same |
| 8 | Hostile API client | bad branch names, both or neither of `snapshot` and `edits`, unknown fields, missing objects, a branch that does not exist | a corrupt queue or a crash | the request's shape checked first; refusals before anything is queued | `hostile_landing_requests_are_refused` |
| 9 | A member who lost access while a change waits | reads the answer | learns whether a hidden path changed | access decided before the fast path | `bug_1104_a_submitter_who_lost_access_is_told_nothing_of_what_changed_since` |
| 10 | A non-admin who may read `.veilrules` | a merge keeping an older side's rules | unprotects `main` | the rules judged against the default branch's tip at every move | `bug_1102_a_merge_never_lets_a_non_admin_change_the_branch_rules` |
| 11 | A pusher | pushes a change on one the server holds off the branch | a change dropped, `landed` said | the stack is every change between the tip and the pushed one | `bug_1103_a_landed_stack_brings_every_change_the_branch_lacks` |
| 12 | Any participant | lands after a pause, or with a view the service does not keep | stalls every landing on the branch | no walk in the service: incremental projections, background fills | `bug_1106_…`, `bug_1100_…` |
| 13 | Ordinary agents | many one-line changes in a 30,000-file folder | the server out of memory | batches bounded in bytes | `bug_1107_…` (in a child process) |

### 13.20 S28: packs, staged uploads, checks several at once (built)

Design: `docs/design/server/storage-and-cost.md` §7 (and §8, which S29
builds on it). Code: `crates/veil-server/src/pack.rs` (the format, each
server's lookup maps, discarding), `store.rs` (`Objects`: reads through
packs, staging), `sync.rs` (`upload`, `push`), `migrations/0013_packs.sql`.
Nothing changes for `vl` or on the wire.

* **Upgrading to S28 is not rolling** (decision, 2026-11-08, BUG-1158):
  stop every server, run `veil-server migrate`, start them all on S28. A
  server before S28 reads objects only under their own keys and cannot read
  packs, so beside an S28 server it would answer "missing object" for
  everything S28 stored (no leak, no loss: S28 servers serve it). No cheap
  sign tells an S28 server that an older one still runs, so this is the
  deployment rule, not a check. Receipts without a pack (from servers
  before S28) are not accepted.
* **A pack** is one storage object, `p/<project>/pack/<name>` (`name`: 128
  random bits in hex), never edited in place:
  `"veilpack3\n" ‖ count u32be ‖ index ‖ entries`. The index, at the front,
  is `count × (id 32 ‖ offset u64be ‖ len u32be)`, sorted by id; **each
  entry is the object's id, the length of its encoding (u32be), then its
  S27 encoding**, and the slot spans all three. Object ids stay the BLAKE3
  of the canonical encoding. The index is read with one ranged `GET` of
  the first 64 KiB (a second for a larger index); an object with a ranged
  `GET` of its slot. **Every read checks the id and the length the entry
  starts with against its slot before it uses a byte of it**, a `Range`
  read too (`pack::entry`; a range far into a large object reads the
  entry's head first, then the range): the id ties the slot's start to the
  object, the stated length its end, so a wrong slot (a damaged index, a
  merger's mistake, a boundary moved between two neighbours) is an error,
  never another object's bytes (BUG-1154, BUG-1394, BUG-1497); a whole
  read is also decoded and checked against the id. **The slots must tile
  the pack exactly** (`pack::parse_index`: by offset, each starts where
  the one before ends, the first at the index's end, the last at the
  pack's end), and each entry's stated length says where that boundary
  must be, so a read never leaves its slot. `veilpack2` (S28 before cycle
  4: entries without their length; never deployed) is not a pack to this
  reader. S29 merges packs by reading indexes and copying entries, and
  drops an object by writing a pack without it.
* **The `packs` table** (migration 13) has a row for every pack in storage:
  *staged* (an upload's, with its uploader), *listed* (its objects are the
  project's) or *discarded* (its storage object is deleted after the row
  says so). A staged row turns listed or discarded once: the push's
  transaction updates it (locking the row) and a discard updates only a
  staged row, so a listed pack is never deleted and a discarded one never
  listed.
* **Uploads are staged and recorded** (BUG-930, BUG-1157). `POST …/objects`
  checks each frame as before (S27's decoding bounds, the hash, canonical
  decoding, the format), writes a *staged* row for each pack of the request
  (at most `pack::MAX_OBJECTS`, 262,144 objects a pack, with the uploader;
  one database commit per pack, so one per `vl` upload request, apart from
  the push's one), then the pack: one storage write per pack (one per `vl`
  upload request).
  Each receipt is `MAC(project ‖ person ‖ id ‖ pack) ‖ "." ‖ pack`. A staged
  pack is nobody's: its objects are read only by a push or API commit of
  that person that shows its receipts, through `Objects::get_staged`, and
  cached under keys of their own (`Objects::staged_key`, in the object and
  tree caches), so no read of the project ever answers a staged object.
  **An upload of objects that a pack the same person staged on this server
  holds all of** (a push that lost a race, uploaded again by `vl`'s next
  try) gets that pack's receipts, with no new pack and no commit.
* **What counts as uploaded** (BUG-1155): only an object its receipt's
  pack holds, where that pack is the pusher's and staged or listed (one
  statement: the rows). A receipt of a discarded upload is worth nothing,
  and a staged object is read from its pack only, never looked for in the
  project's store instead, so naming a guess of hidden content with an old
  receipt gets the answer a wrong guess gets.
* **A push** reads the staged packs its receipts name (their indexes, from
  memory on the server that took the upload, or by bisecting the sorted
  index in storage with 64 KiB ranged reads), checks every new snapshot as
  before, and then, when something lands:
  * lists a staged pack **as it is** if its checks read every object in it
    (what a `vl` push uploads is exactly what the checks read: §13.5);
  * puts the objects the checks read from any other staged pack, and the
    objects the server made (the graft's trees, completed snapshots, the
    pusher's signed projections), into **one pack of its own** (split at
    `pack::MAX_OBJECTS`, 262,144 objects a pack);
  * lists them in its one transaction (one statement more), and refuses
    with 409 if a pack it names was discarded first (`vl` uploads again);
  * discards every staged pack it did not list (every delete tried,
    whatever another answers: BUG-1498).
  **A push its checks refuse** (a secret in plain text, a path the pusher
  may not write, anything answered before its transaction) discards its
  staged packs and deletes its own, so **a refused upload stays in the
  store only for the push that refuses it**. **A push that only lost a
  race** (409, or every update not on the tip) passed every check: its
  uploads stay staged for the next try (above), and its own pack, if it
  wrote one, is deleted once the database shows its transaction did not
  list it.
* **A push's own pack is recorded too** (staged, the pusher's) before it
  is written, and its transaction lists it, so **every pack in storage has
  a row**, whatever stops the request (BUG-1399): one database commit more
  per own pack for a push that writes a pack of its own (the server
  completed its snapshots or made projections), apart from its one
  transaction. **A push runs to its end in a task of its own**: a client
  that goes away (a stopped `vl push`, a dropped connection) stops the
  request, not the push, whose clean-up then discards what it did not list.
* **What storage holds that no push listed** (until S29's job removes the
  staged rows older than its grace, and their packs, and the packs of
  discarded rows that a failed delete or a stopped server left in storage:
  BUG-1498, `storage-and-cost.md` §8): staged packs, each
  with its row: of each push that lost every race since (one per upload
  request, reused by its retries on the same server; one per server a
  retry reaches), of uploads no push followed, and those of a request run
  again after a database or store error (`db::retry_requests`). That is at
  most what each person uploaded, as before S28, and S24's per-person
  limits bound it.
* **An API commit** (S10) reads the objects its receipts name from their
  staged packs, at most 1 GiB, **holding a share of the server-wide bound
  on decoded bytes** (`store::DECODED_IN_FLIGHT`, 256 MiB for every request
  together; a commit naming more takes all of it, so such commits run one
  at a time: BUG-1156), **taken before it reads them**: what they decode to
  comes from each entry's first bytes, then the share, then the objects one
  at a time (BUG-1397); it stores what it keeps loose once every check
  passed, as before, and discards the staged packs when it is answered
  (not after a lost race: the caller may try again with the same receipts).
* **Reads.** `Objects` finds a project's object in its cache, then in the
  indexes of the listed packs this server holds (per project, newest pack
  first, each a sorted array of 48 bytes a slot, searched by bisection;
  **128 MiB for every project together, by their real memory**, each
  project's entry and each pack it names counted). Past the budget the
  indexes used least recently are unloaded, those of the project in use
  too, and then the entries of projects used least recently, never the one
  in use: a lookup that needs an unloaded index reads it again from storage
  (`pack::Packs::find_paged`), so **a project of any size always reads**
  (BUG-1395, BUG-1396). Weights are read from the maps under one lock, so
  eviction and additions never miscount. Such a lookup searches the loaded
  indexes and names the unloaded ones **under one read of the map**, then
  reads those from storage, so together they cover every listed pack and
  **no lookup answers "missing" for a stored object**, whatever other
  lookups page in or out meanwhile (BUG-1495). **Every pack index held in
  memory outside the lookup maps holds a share of one server-wide bound**
  (`pack::INDEXES_HELD`, 96 MiB for every request together, of which the
  staged-index cache may hold 32 MiB), taken before the first bytes are
  read or the index is built and covering all memory the operation holds
  (the index bytes, the parsed index and the parse's working copy for
  `read_index`; the index bytes and parsed index for `write_pack`, with
  `pack::MAX_OBJECTS` at 262,144 so a full pack's index takes at most 27
  MiB to read, 23 MiB to build and 12 MiB to hold, never clamped:
  BUG-1621): one being read for a lookup or a listing, the pack a push
  writes (its share released as soon as `listed()` enters the index in the
  lookup map, before `projected()`), and a push's staged uploads' (when not
  in the staged-index cache, `pack::Packs::staged_slots` bisects the sorted
  stored index by 64 KiB ranged reads under one 64 KiB share and keeps only
  the slots its receipts name and the object count, never reading the whole
  index; each project also has its own fair share of the active bound so
  one project's load can never starve another's: BUG-1620). A listing loads
  each index as it is read and leaves the rest unloaded when the bound is
  full (a lookup reads them later); a request that gets no share within
  10 s is answered 503 `busy` with `retry_after_ms` (and `Retry-After`)
  across every reader (`sync::Source`, projections, viewer-graph fills,
  queries, search), never 500 and never with an index held outside the
  bound (BUG-1496, BUG-1622). Then
  loose (objects from
  before S28, and what grants, API commits, the deriver and the search
  index store). After a miss in both it reads the project's listing again
  (one statement, unless a listing began after the miss: it holds every
  pack listed before) and the indexes of packs it does not know, so a
  server reads what another server's push listed. A push's own packs join
  the map at its commit. `Range` (S5) is of the object: a plain packed
  object is read for those bytes only (and its id); a compressed one
  decoded whole, as before.
* **Neighbours read together** (BUG-1152). Before it answers, a `fetch`
  reads the packed objects it will send that are not cached, per pack and
  by offset, slots at most 64 KiB apart in one ranged request of at most
  2 MiB (8 at once, each holding a share of the bound on bytes read ahead,
  or not prefetched), and caches them, each entry's id and each object
  checked, **each object's decoding holding a share for what it declares**
  (or not read ahead: BUG-1159).
* **What a push stores is counted where it is stored** (BUG-1398): a push
  and an upload run in a scope of their own (`store::own`), and the writes
  made in it are theirs (`Objects::own_writes`, `storage_push_writes` for
  `veil-bench load`); the work they spawn (the deriver, the search index)
  and every other request (pulls' projections, grants' trees) are not. A clone asks a level of many snapshots at once, whose objects
  lie in upload order in the same packs.
* **Permissions are unchanged and per object.** Packs change where objects
  are stored, never who may read them: every route reads one object at a
  time through `Objects` after the same checks (S1's path walk, S5's grant
  and chain), a pack is never sent, and "not found" stays the answer for
  objects that are not reachable, packed or not.
* **Checks several at once** (BUG-865). A push checks up to 8 new snapshots
  at once, 64 ahead at a time, on the guess that each new parent is
  completed to itself (an admin's, or anyone's who sees all it changes): a
  right guess has exactly the inputs of checking one at a time, so the same
  answer; a wrong one is checked again in order; results and the first
  error are taken in order. When most guesses of a window are wrong (a
  pusher the server completes every snapshot for), the rest is checked one
  at a time.

#### Threat review

Attackers outside the trust boundary (§3.1): a participant crafting
uploads, receipts and pushes; a reader without access to a folder; another
participant racing them. The server, its database and its object store are
trusted (with code; never with secrets' plaintext).

| # | Threat | Defence | Test |
|---|---|---|---|
| 1 | A pack hands a reader objects of folders they cannot see | no route sends a pack; every object is read one at a time after its path or chain check | `grants::object_routes_serve_only_what_a_grant_reaches`, `leaks::…`, `sync::…` (all on packed objects now) |
| 2 | Pack membership confirms a hidden object (one in the same pack as a visible one) | lookups answer only what the route's check reached; a hidden object of the same pack gets the answer a random id gets | `grants::object_routes_serve_only_what_a_grant_reaches` |
| 3 | A refused plain-text secret stays stored (BUG-930) | uploads are staged; the refusing push discards them; a landing push discards what it did not list | `packs::a_refused_push_deletes_its_staged_upload`, `packs::an_unread_plain_text_secret_beside_a_landing_push_is_not_kept`, `changes::bug_930_…` |
| 4 | Another person's staged upload read or claimed, or a discarded upload's receipt used to confirm a guess of hidden content (BUG-824's class, BUG-1155) | receipts bind person and pack; an object counts as uploaded only if its receipt's pack, the pusher's and not discarded, holds it; staged objects are read only from their pack and never cached as the project's | `packs::receipts_hold_only_for_their_person_and_pack`, `packs::bug_1155_…` (a push and an API commit) |
| 5 | A receipt moved to another pack, or a crafted pack name (`../`) | the MAC covers the pack; names are 32 lowercase hex digits | same |
| 6 | A race lists a pack another push of the same person discards, or deletes a listed one | the primary key decides; discard deletes only after its row won; a push deletes its own pack directly only if its transaction never began | `pack::…`, `packs::a_refused_push_deletes_its_staged_upload` |
| 7 | An object a push's checks never read kept in the store (an upload a push names but never checks) | only what the checks read is listed or copied | `packs::a_push_is_one_storage_write_and_reads_come_from_its_pack` (crafted pushes upload superseded trees) |
| 8 | A damaged or hostile index (counts, offsets past the end, unsorted, overflow, a slot naming another object's entry) | parsed with every bound checked; every read, ranged ones too, checks the id its entry starts with; whole reads are checked against the id | `pack::tests::…`, `store::tests::bug_1154_a_wrong_slot_never_serves_another_objects_range` |
| 11 | API commits naming large uploads exhaust memory (BUG-1156) | held under the server-wide bound on decoded bytes | `packs::bug_1156_…` (six at once) |
| 12 | Push attempts that lose races fill storage with copies (BUG-1157) | retries get the earlier upload's receipts; every staged pack recorded | `packs::bug_1157_…` |
| 9 | Checks run on a guess answer differently from one at a time | a guess is used only when its inputs are the real ones; results and errors in order | `packs::bug_865_…` (an admin's 70 snapshots, every guess right; a developer's 70, every guess wrong), the whole `server_hub` suite |
| 10 | A server serves a stale "not found" for an object another server just listed | after a miss, the listing is read again | `packs::a_push_is_one_storage_write_and_reads_come_from_its_pack` (a second server) |

#### Measured

`scripts/bench-server.sh 1g` through `bench-quiet.sh` (PostgreSQL 17 and
MinIO in Docker, release builds, the same `vl` and `veil-bench`; the base
server through `SERVER_BIN`), one run each, back to back on a quiet
machine (load 13 → 9 and 9 → 11), 2026-11-08; memory is the server's
`VmHWM`. Storage writes and load: the earlier harness and `veil-bench load`
(one project, 10 agents, 15 s).

| | `integration` @ `6fa552c4` | S28 (`891ef104`) |
|---|---:|---:|
| push, initial (10,022 snapshots, 327,017 objects): time | 252.7 s | **99.3 s** |
| push, initial: server peak | 1,254 MiB ⛔ | **888 MiB** |
| push, initial: storage writes | 327,017 (one per object) | **110** (one per 8 MiB upload request) |
| clone, full: time | 68.5 s | **59.8 s** |
| clone, full: server peak | 1,786 MiB ⛔ | **964 MiB** |
| clone of one directory: time / server peak | 4.7 s / 1,343 MiB ⛔ | 8.0 s / 895 MiB (BUG-1152) |
| load, own branches: storage writes per landing (the push's own) | 9.0 | 3.0 (**2.0**) |
| load, into one `main` (about 9 lost races per landing): per landing (per push) | 66.5 | 15.4 (**1.5**) |
| load: database commits per landing, own branches / one `main` (the push's own) | 1.58 / 5.2 | 1.38 / 5.0 |
| load: storage reads per landing | 0 | 0 |

After S28's cycle 3 (the read and push paths changed: tiled slots, paged
indexes, the push in a task of its own), `bench-server.sh 1g` @ `7ebc199c`,
on a busy machine (load 103 → 21, so times are noisy): push 87.8 s and
890 MiB, full clone 54.5 s and 929 MiB, clone of one directory 8.7 s and
895 MiB; every case under the gates. After cycle 4 (`veilpack3` entry lengths,
held indexes bounded under `pack::INDEXES_HELD`), on an isolated 8-vCPU, 16 GB
Boat machine: push 157.5 s and 905 MiB, thin clone 21.5 s and 853 MiB, full
clone 98.6 s and 904 MiB, clone of one directory 16.4 s and 840 MiB; every case
under the gates.

**BUG-1089 and BUG-1000** (bisected: `31639c3` 972 MiB, `d8cf2b2` 967 MiB,
`b2478b5` 1,356 MiB): objects read from S3 were cached as slices of the HTTP
client's read buffers, each small object pinning a whole buffer while the
cache weighed only its bytes; S27's smaller encodings put about 2.5 times
as many objects in the cache. A heap profile at the push's peak put 678 MB
of 1.41 GB live there. `Objects` now copies what the store answers before
caching it (`store::owned`).

#### Reverting

Revert the merge **only if no server ran it on real data**: a server
before S28 cannot read packed objects (it finds no loose object), and it
would read receipts with a pack as invalid (and the upgrade is not
rolling, above). Once a server has listed packs,
going back needs every listed pack's objects written out loose first; no
tool does that yet. Migration 13 only adds a table (harmless to an older
server).

### 13.21 S3: thin clones, fetch on demand (as built)

Milestone S3 of `docs/design/server/phase-2-thin-clients.md` (§4.2, §5.4,
§9): the client half of `docs/design/scale/6-partial-clone.md`, re-aimed
at the server, with **no full graph**. Code: `veil-core/src/promisor.rs`
(the read path, the cache, eviction), `Repo::exact` and `Repo::deepen`
(`repo.rs`), `crates/vl/src/thin.rs` (the connection and `vl partial`),
`hub.rs` (the thin pull). One server change: `history` answers pages.

#### The design as built

* **`vl clone` is thin by default** on a server project (owner decision 3
  of the phase-2 design); `--full` keeps S1's clone. A thin clone fetches
  the branch tips (one `history` page holding just them) and the trees and
  files of the branch it checks out, into `.veil/cache/`. `--only DIR`
  clones keep their S1 form (not thin).
* **Repository format 9** (`docs/FORMAT.md`): format 8 plus the
  `partial: {remote, cache_limit}` marker. S3's release wrote thin clones
  at it (every other repository at 8). Since S11, format 10 has everything
  9 has: thin clones are format 10 with the marker, and `vl upgrade` brings
  a format-9 thin clone to 10 keeping it (§13.27). An older vl refuses
  both by number.
* **Two areas.** `.veil/objects/` holds every snapshot the clone fetched and
  everything it made; it is never evicted, and `put_raw` always writes it
  (a local write is never skipped because the cache holds the object).
  `.veil/cache/` (an `ObjectStore` of its own) holds the fetched trees and
  files and is the only area evicted.
* **The read path** (`ObjectStore::read_raw`): the main store, the cache,
  then the server. The object's place is the snapshot and path where this
  process met it, recorded when the tree naming it was decoded (a compact
  map: child → parent and entry index). The client asks S1's `fetch` for
  that id at that place; the server checks it against the person's
  projection. What arrives is re-hashed (BLAKE3), decoded and checked
  storable before it is written to the cache. An object met only under a
  local commit is asked for at the same path under the remote's tips.
  * the server's 404 ("no such object at that path that you can see") is
    `VeilError::Missing`, a real redaction;
  * a server that cannot be reached, any other answer, a command with no
    connection, or a tree or file whose place this process did not record
    (BUG-1142) is the new `VeilError::Unavailable`, which is not
    `is_unreadable()`: every site that leaves a hidden object out fails
    instead. Its message names the server and the path, never an id.
  * **Where `Missing` comes from**, audited by
    `thin::every_producer_of_missing_is_audited`: the server's refusal at a
    place under a snapshot on the server; a snapshot beyond the boundary
    (a read asked for a snapshot); "not held" while fetching is off (gc,
    fsck, maintenance, which classify it).
  * An object met under a local commit is asked for at the same path under
    the commit's nearest ancestors on the server, then the remote's tips
    (BUG-1144).
  * **The locator** records every tree met (a place is the chain of trees
    above an object) and every file the main store's packs do not hold (the
    cache's may be evicted and read again, BUG-1147), compactly (an 8-byte
    key, 16 bytes a place; the parent is checked to name the object), at
    most 1,500,000 places and parents: 35 to 66 MiB held, 51 to 82 MiB at
    the peak, measured with a counting allocator (BUG-1149). Past it, a read
    of what is not held is `Unavailable`.
  * What is on the server is judged from the remotes' tips as the view has
    them, refreshed on every change of the view (a pull in a long-lived
    process is seen at once).
* **No full graph.** A snapshot the clone lacks is beyond its boundary.
  History is read through two types (see "Revised: names and fetching"
  below): `Held` reads never fetch (the history index, gc, maintenance,
  eviction's pins, this clone's own history); `Exact` reads answer as a full
  clone (a single read fetches a 2,000-snapshot page at the boundary, a walk
  pages in what its range reaches). Revision names its held history cannot
  decide are asked of the server. Without the server: `Unavailable`.
  A later pull fetches the new snapshots down to what it has, a page at
  most, and the content of the checked-out branch's tip only.
* **Checkout fetches ahead.** Before a thin clone's working copy moves
  (`move_working_copy`), the trees and files that differ are fetched a
  level at a time, in batches of at most 1,000 objects and about 8 MiB by
  the sizes tree entries carry (`ObjectStore::prefetch_diff`), so a lost
  server or a full cache fails the move before it writes anything, even its
  journal. **Before an operation that moves the project directory's working
  copy is published** (`Transaction::commit`: any command, `new`, `edit`,
  `merge`, `rebase`, `cherry-pick`, `restore`, `undo`, `op restore`), its
  target is fetched ahead, so a failed one records nothing (BUG-1146). A
  stale directory that cannot be brought up to `@` stays as it is, with a
  warning and nothing recorded, so `status`, `undo` and `partial limit` run.
* **The cache's bound** (default 4 GiB, `--cache-size`, `vl partial
  limit`): when a fetch would pass it, the cache is evicted down to 80 %,
  least recently written first. **Pinned, never evicted:** everything,
  trees *and files*, of every workspace's working-copy snapshot (a parked
  workspace's too: it is checked out again as it is) and of the checkout
  record (and of an unfinished move's target); and the trees only, not the
  files, of the server-side bases of the snapshots only this clone holds
  (for gc and fsck). A pack holding pinned objects is
  rewritten with them before it is removed, so a reader whose pack
  vanished finds them again. The bytes of a batch not yet on disk count in
  the bound with what is (BUG-1145). When what is pinned alone passes the bound,
  the fetch fails with a clear error (never an eviction loop); a clone
  whose checkout passes it is refused. Snapshots and local work are in the
  main store; the op log's views name snapshots, all of which are there.
* **Also pinned: the trees (not files) of the server-side bases** of the
  snapshots only this clone holds, so gc and fsck can tell their gaps
  (BUG-1148).
* **gc, fsck and maintenance never fetch.** A gap they meet is classified
  (`ObjectStore::classify_gap`, BUG-1143): **the server's** when its
  snapshot is in the remotes' history (from every operation's remote tags),
  or when a parent, down to one there, names the same object at the same
  path (fsck: a note, "not fetched"; gc: its mark skips it); **lost** when
  only this clone's own snapshots name it (fsck: corrupt; gc: incomplete,
  so nothing is deleted, as in a full clone); **unknown** when the trees
  that would tell are not held (fsck: a warning; gc: incomplete).
* **`vl partial full`** fetches every snapshot and object into the main
  store, copies what only local commits reach from the cache (or the
  server), rewrites `repo.json` at format 8 without the marker (the commit
  point), then removes the cache.
* **Server:** `POST …/history` takes `limit` (revision 4; 3 is S5's read grants, BUG-1140): every tip, then
  their ancestors, those of the newest children first, at most `limit` in
  all. Without `limit`, the whole history as before.

#### Measured (2026-11-07)

`scripts/bench-server.sh 1g` through `bench-quiet.sh` (load 15.4 before,
7.0 after; PostgreSQL and MinIO, release builds, ext4 NVMe): 35,000 files,
1.15 GB working tree, 10,022 snapshots.

| Case | Time | Client peak | On disk |
|---|---:|---:|---:|
| clone, thin (default) | **8.0 s** | **333 MiB** | 0.43 GB in `.veil` |
| clone, full (`--full`), same run | 56.4 s | 440 MiB | 1.93 GB |
| `vl log -n 20` in the thin clone (fetches history pages) | 5.5 s | 77 MiB | |
| `vl status` in the thin clone, clean (3 runs) | 9.8, 1.4, 0.08 s | 115 MiB | |

After review cycle 1 (BUG-1140..1145 fixed; same profile, 2026-11-07, load
20.5 before (the quiet wait ran out) and 9.9 after): thin clone **7.6 s, 366
MiB** client peak, 0.43 GB in `.veil`; full clone 67.1 s, 457 MiB; `log -n
20` 4.7 s; `status` in the thin clone 8.9, 0.63, 0.09 s. Snapshot reads that
page history in, and the fetch-ahead's byte-bounded batches, cost nothing
measurable on these cases.

After review cycle 2 (BUG-1146..1149, 1260 fixed; the clone path now notes
the files of cache packs): the same profile ran at load 96 (the quiet wait
ran out), and every case slowed with it (initial push 384 s against 222,
full clone 105 s against 67): thin clone 13.6 s, **332 MiB**; `log -n 20`
11.3 s; `status` 31.3, 0.68, 0.47 s. Back to back on one machine at load 40
to 70, thin and full clones of a 35,000-file project (31 snapshots) are
alike: `status` 0.65, 0.21, 0.04 s (thin) and 0.64, 0.17, 0.05 s (full);
clone 1.56 and 1.22 s, 140 and 132 MiB. Nothing on the clone path costs
measurably more; the 1 GB numbers are to be taken again on a quiet machine.

After review cycle 3 (the redesign: names asked of the server, `Held` and
`Exact`, one rule for moves), the same profile at load 35.6 before (the
quiet wait ran out): thin clone **7.9 s, 337 MiB** client peak, 0.43 GB in
`.veil`; `status` 7.7, 0.49, 0.10 s; `log -n 20` 6.0 s; full clone 100 s,
456 MiB. Back to cycle 1's level for the thin clone.

After the redesign's review cycle 1 (boundary generations from the
server, `q/resolve` filtered first, history pages from reached snapshots
only), the same profile from load 12.5 (quiet) to 96.6 by its end:
`log -n 20` in the thin clone **0.14 s** (6.0 s before: the history index
takes the boundary's generations from the server and pages nothing in),
59 MiB; `status` in the thin clone 0.27 s, 62 MiB; thin clone 19.4 s, **337
MiB**, 0.43 GB in `.veil`; full clone 90.3 s, 418 MiB. The thin clone's
time follows the load that rose during the run: back to back at load 40 to
55, thin and full clones of a 35,000-file project (31 snapshots) are alike,
clone 1.93 and 1.39 s (thin) against 1.55 and 1.73 s (full), 137 to 143
MiB, `log -n 20` 0.03 s against 0.05 s, as in cycle 2.

* A thin clone's time and memory follow what it checks out (the tip's
  35,000 files), not the history: it holds 2 snapshots of 10,022.
* The first `vl status` after a clone re-reads the files written within
  the stat cache's racy window, thin or full alike: on a 10,000-file
  project (`.scratch` experiment, 31 snapshots) thin 0.12, 0.10, 0.01 s and
  full 0.19, 0.10, 0.01 s. The benchmark measures the full clone's status
  only after two pulls, so its 0.09 s is a later run.
* `log -n 20` fetched 2,000-snapshot pages and ran the walk again after
  each until cycle 3 (seconds on a long history). Since the redesign's
  review cycle 1 the boundary's generations come from the server
  (`q/generations`), so the walk pages in only the part of history it shows.
* The server's 1 GB memory gate is missed by every case of this run from
  the initial push on (push 1,257 MiB; the server keeps that RSS): server
  push memory is another stream's work (BUG-1000 for clones). A thin clone
  adds 75 MiB to the server's peak; the full clone 652 MiB.

#### Threat review (the partial-clone design's, and phase 2's rows 9, 16, 18)

| # | Threat | As built | Test |
|---|---|---|---|
| 1 | an unfetched object read as hidden | `Missing` only from the server's own refusal at a place under a snapshot on the server, or a snapshot beyond the boundary; a tree or file without a recorded place is `Unavailable` (BUG-1142); every site that reads, and every site that makes, a `Missing` in `veil-core` is listed in an audit table | `core_sync` `thin::an_unreachable_server_is_unavailable_never_hidden`, `a_command_without_a_connection_fails_instead_of_hiding`, `s3r_an_object_without_a_recorded_place_is_never_hidden`, `every_site_that_reads_missing_as_hidden_is_audited`, `every_producer_of_missing_is_audited` |
| 2 | the server sends what the person may not see | the client asks only for ids met in trees the server gave it, at that path; the server checks each (S1) | `server_hub` `thin::a_thin_clone_receives_nothing_its_person_may_not_see` (dev and anyone, every revision shown, then `vl partial full`; cache packs scanned decoded) |
| 4 | a tampered or wrong object | re-hashed (BLAKE3), decoded, checked storable before use; a snapshot where a tree entry was asked is refused | `thin::a_tampered_object_is_refused_and_never_cached` |
| 5 | gc and fsck in a thin clone | never fetch; a gap of the server's history is skipped (a note), one only local snapshots name is lost work (corrupt; gc deletes nothing) (BUG-1143) | `thin::gc_in_a_thin_clone_never_fetches_and_keeps_local_work`, `s3r_fsck_in_a_thin_clone_reports_lost_local_work` |
| 6 | eviction of local work | local writes go to the main store, even when cached; only the cache is evicted | `thin::local_work_is_never_in_the_cache_and_survives_eviction` |
| 7 | the server prunes what we relied on | not reachable yet: the server has no gc (anchors.json deferred to S29) | — |
| 8 | eviction racing readers | pinned objects rewritten before a pack goes; a vanished copy is fetched again | `thin::eviction_keeps_the_bound_and_the_pins` |
| 9 | push from a thin clone leaves the receiver incomplete | the push sends what differs from the parents (S1's `Introduced`); the server checks closure | `server_hub` `thin::a_thin_clone_holds_the_tips_…` (push, then a full clone pulls, checks out and passes `fsck`) |
| 11 | fetch storms, a thrashing cache | stops at the bound with an error, bytes in flight counted (BUG-1145); a too-large checkout is refused at clone, a too-large move before it is recorded | `thin::a_full_cache_fails_cleanly`, `server_hub` `thin::the_cache_stays_under_its_bound`, `s3r_a_checkout_past_the_cache_bound_fails_before_writing` |
| 12 | the server is unreachable | fails before writing anything (the checkout fetches ahead, before its journal); local work goes on | `server_hub` `thin::a_lost_server_is_a_clear_error_never_a_hidden_file` |
| 14 | format and older vl | the marker only at format 9 or later, and format 9 only with it; refused by number by an older vl | `thin::the_partial_marker_needs_format_9_and_back`, `format_compat`, `thin::a_format_9_thin_clone_upgrades_to_10_keeping_its_marker_and_still_fetches` |
| — | no full graph, yet history read as a full clone reads it | snapshot reads fetch history pages at the boundary, the history index never does; ancestry and log page through `history`; without the server, `Unavailable` (BUG-1141); pages are revision 4 (BUG-1140) | `thin::ancestry_beyond_the_boundary_asks_the_server`, `server_hub` `thin::a_thin_clone_answers_as_a_full_clone`, `s3r_each_protocol_revision_announces_one_thing`, `server_hub` `thin::history_answers_pages`, `s3r_show_of_a_snapshot_whose_parent_is_beyond_the_boundary`, `s3r_show_of_a_merge_whose_other_parent_is_beyond_the_boundary`, `s3r_blame_in_a_thin_clone_is_the_full_clones` |
| — | a local commit's object after the server moved on | asked under the commit's nearest ancestors on the server (BUG-1144) | `thin::s3r_a_local_commits_unchanged_directory_is_found_after_the_server_moved_on` |

#### Reverting

Revert the merge commit. Thin clones made meanwhile are format 9 (10 since S11), which
the reverted vl refuses by number (nothing is misread): run `vl partial
full` in each before reverting, or clone again. The server change (the
`limit` of `history`, revision 4) is additive: an older client never sends
it.

#### Revised: names and fetching (S3 cycle 3)

Review cycle 3 found seven bugs (BUG-1261..1267) with two roots: revision
names answered from the history a thin clone holds, and fetching keyed on
the wrong thing. After three cycles the two mechanisms are redesigned, not
patched route by route. This subsection is the design; the bullets above it
describe what it replaces.

**1. Names: the server answers what held history cannot decide.**

* **Route** `GET /v1/projects/{p}/q/resolve?prefix=P[&from=ID,…]` (protocol
  revision 5; `from` since the redesign's review cycle 2, which an older
  server ignores): over the caller's own projected history (the viewer graph of S13,
  filled as for every query; `warming` while it fills), the snapshots
  whose id starts with `P` (hex, 4 to 64 digits) or whose change id starts
  with `P` (as written, letters k–z, 4 to 32). At most 16 of each, and
  whether more matched. A change the caller cannot see is not in their
  history (its projection is its parent's, whose change id differs, and is
  dropped), so nothing hidden is named, and "nothing matched" is the answer
  for anything else. One request, no history pages.
* **Revision resolution** in a thin clone keeps a full clone's order
  exactly (`@`, `root`, `ws@`, tags, remote tags, `tag:`, a full id, a
  change id prefix, a snapshot id prefix, a hidden version). The two prefix
  steps take the held matches *and* the server's (one request; each
  snapshot it names is fetched alone, as a page of one), and apply the same
  rules (one match, divergent, ambiguous) to the union. A typo costs one
  request and fetches nothing. A server below revision 5 gets held matches
  only.
* **The pull's tag check** (BUG-105: no tag named like an id of the
  history) asks the same lookup for each new tag name that looks like an
  id, with the held history: a name the server's history has as an id is
  never a local tag.
* **Hidden versions** (an earlier version of a change: `evolog`, `op log`)
  are this clone's own and held: their lookup reads held only.

**2. History reads are typed: `Held` or `Exact`.**

* `Repo::held()` returns `Held`: reads and walks of what this clone holds
  (`snapshot`, `ancestors`, `topo_children_first`, `visible`). They never
  fetch; a walk records where it met the boundary.
* `Repo::exact()` returns `Exact`: answers a full clone's. A single read
  (`snapshot`) fetches a page at the boundary; a walk (`ancestors`,
  `topo_children_first`, `visible`, `range(include, exclude)`) is the held
  walk run again after each page the boundary it met needs, so it pages in
  only what its own range reaches (bisect: from `bad` down to `good`); a
  query on the history index runs as `Exact::run`. `Repo::snapshot`, the
  read of a snapshot a command names, is `Exact::snapshot`.
* Every caller chooses one by type: bisect, evolog, revision resolution,
  merges, rebases and everything shown to the person use `Exact`; the
  history index, gc, maintenance, the pull's tag check (with the server
  lookup), the pins of eviction and other bookkeeping use `Held`. The text
  audits of snapshot reads are replaced by this split, and a test compares
  a list of commands' output in a full and a thin clone of one history.

**3. Fetching keyed on what is materialised, and on the clone's own
server.**

* **One rule for moves:** before an operation is published, the working
  copy a directory will hold after it is fetched ahead: the project
  directory's workspace (the one it stays attached to, or the one a `ws
  switch`, or its undo or redo, attaches it to: `Transaction::attaches`),
  from what the directory holds now. On failure nothing is published and
  the command fails. A workspace no directory holds (`vl ws new`) needs
  nothing until it is attached, or synced by `vl ws exec`, which fetches
  before it runs.
* **"On the server" is the clone's own server:** the snapshots reachable
  from the `partial` remote's tags (`<remote>/…`) only, everywhere it is
  judged (the read path, eviction's pins, gc, fsck). A second remote's
  snapshot is never taken for the server's. A thin clone fetches on demand
  from its own server only, so a pull from another remote is a full pull:
  its snapshots and everything they reach go to the main store (never
  evicted, never asked of the clone's server).
* **gc's roots:** eviction pins the trees (not files) of the server-side
  bases of every local-only snapshot gc roots: those of every operation
  the op log keeps (rewritten versions included), not the view's alone, so
  `classify_gap` can always compare and gc completes.

**As built (S3 cycle 3).** `q/resolve` is `query::resolve_prefix`
(`veil-server`); the client asks it through `Promisor::resolve`
(`revset::server_names`), and a server below revision 5 gets held answers
only. `Held` and `Exact` are in `repo.rs`; the old walks are private to it,
so every other module states which it needs; bisect uses
`Exact::range(bad, goods)`, `x..y` revsets `Exact::range`, `::x` and the
visible set `Exact`, the embargo release listing the history index under
`Exact::run`. `Transaction::attaches` carries a switch's target to the
fetch-ahead. Tests: `server_hub` `thin::a_thin_clone_answers_as_a_full_clone`
(nine commands, full against thin), the reviewer's `s3r3_*` reproductions,
`thin::every_working_copy_move_past_the_cache_bound_records_nothing`.

**Revised again (S3 redesign review, cycle 1).**

* `q/resolve` answers only from what the caller sees: rows in a fixed
  order, a chunk at a time, those withheld (in the query), unreached by
  the viewer's branches, or of a change the caller cannot see dropped
  before anything is counted; it stops at 17 that count (BUG-1268, 1269).
  (A history page also started only from snapshots the branches reach;
  cycle 2 replaced that rule, BUG-1319, below.)
* **Generations at the boundary come from the server** (`POST
  …/q/generations`, protocol revision 6; the viewer graph's, the history
  index's own arithmetic). A thin clone's index then has an exact
  generation for every snapshot it holds without the ancestry below, and an
  `Exact` walk pages in only what its range reaches: a 6-snapshot range of
  a 40-snapshot history reads at most 6 two-snapshot pages, never 20
  (BUG-1291). Without the server an `Exact` walk fails; a `Held` one goes
  on with lower bounds it never persists and `Exact` never uses. (S13's
  query API answers pairs of server snapshots only, and a thin clone's own
  commits are not on the server, so its index stays the walker, with the
  server's numbers at its edge.)
* **The split is closed** (BUG-1290): `Repo::graph`, `visible_among`,
  `visible_embargoed` and the index are private to `repo.rs`,
  `ObjectStore::snapshot` to the engine; `Held` and `Exact` carry every
  history read. Descendant rewriting (`rebase_descendants`), `check_current`
  and the served log read `Exact`.
* The remote a thin clone fetches from cannot be removed (BUG-1292); a
  working-copy snapshot never copies an unchanged fetched file into the
  main store (BUG-1293), and `vl partial full` copies what only the cache
  holds for everything the kept history reaches.

**Revised a third time (S3 redesign review, cycle 2).**

* **Names and pages are two questions, with two rules** (BUG-1319).
  *Which snapshot a name means* (`q/resolve`) is answered from the
  caller's projected history as the branches reach it, and as the
  snapshots the clone names in `from` reach it (its own refs on the
  server: at most 64, each the caller's own id, else left out as unknown;
  `Repo::server_roots` finds them, replacing the clone's own commits by
  their parents). *What is below a snapshot* (a `history` page) is
  answered from any snapshot of the caller's viewer graph that is not
  withheld, reached or not: the person was sent it. On the client,
  `Repo::deepen` asks for a page only where a full clone made now would
  hold the snapshot (`Repo::may_page`): below a held snapshot (a parent
  the store saw it lack), or a name the server's branches or the clone's
  own refs and operation log reach. A predecessor `vl evolog` follows to an
  old version nothing here reaches is not found, as in a full clone; the
  history below a clone's old tip after a rewrite elsewhere is read.
  Divergent change ids choose the version the clone's own heads reach,
  exactly (`in_local_history`).
* **One generation arithmetic** (BUG-1316): `graph_index::generation` in
  `veil-core` (WASM-safe: the timestamp clamped to 0 ..= `MAX_STAMP`, one
  more than the highest parent, a root 0), used by the client's history
  index, the server's real graph and every viewer graph. Index layers are
  `VEILCG02`: an older vl's (`VEILCG01`, values up to `u64::MAX - 1`) void
  the index, which is computed again (BUG-1381: kept, a value above
  `i64::MAX` gave the next entry, capped there, a generation below its
  parent's; `docs/FORMAT.md`). A property test checks that the three
  agree on random histories with far-future, negative and equal timestamps
  and several roots.
* **Change id prefixes from the caller's own graph** (BUG-1317): every
  viewer graph row has a row in `view_changes`, keyed by (project, view
  key, change id, snapshot), with its flags (migration 21,
  `view_graph_changes`; a table rather than an index on `view_graph`, whose
  online build on YugabyteDB outlasts the statement timeout under load).
  The migration empties `view_graph` with `TRUNCATE`, in time that does
  not grow with the table (BUG-1383); it is a cache, filled again as
  queries need it, and `q/generations` fills each snapshot it is asked
  about, as a page start is filled, so its answer never depends on what
  the cache holds (BUG-1384). Fills write `view_changes` first. So
  `q/resolve` never reads the real `graph` and starts no fill but the
  branch tips' every query makes. Each step reads at most `Limits::work`
  rows of the caller's graph; past it the request fails asking for more of
  the prefix.
* A pull from another remote asks for every tip (BUG-1318): what a held
  tip reaches goes into the main store too, object by object from what it
  lacks.

#### Not built in S3 (and why)

* **anchors.json** (pinning before a non-fast-forward pull): the server
  keeps every object it has stored (it has no gc yet), so what a clone did
  not fetch cannot disappear. S29's gc must keep a retention window for
  thin clones; the pinning comes with it.
* **Promotion** of cached objects a transaction references: not needed
  while the server keeps everything; pins cover the working set.
* `vl partial widen|narrow PATH`, `vl fetch REV -- PATH`, thin `--only`
  clones (S8's sparse fallback), the mount's folder prefetch (S8), the
  daemon (S6).
* `fsck` in a thin clone does not ask the server whether an unfetched
  object exists there: it is a note.
* The reads that keep to what is held (the history index, gc, maintenance,
  push's walk of what the server has) take the boundary for the end of the
  graph, on purpose; every other snapshot read fetches history there. The
  server decides embargoes and closure itself (§13.5).

### 13.22 S14: blame and file history (built)

`GET …/q/blame?rev=&path=&follow=` and `GET …/q/history?rev=&path=&follow=` answer on the caller's projected history only, like S13's routes (`docs/design/server/phase-3-server-history.md` §12 has the design as built, its bounds and its threat review).

* **Per viewer, precomputed:** the fill of a viewer's graph (S13) also writes their file history (`view_file_history`, migration 0015): for each of their snapshots, the paths it changed in their projected trees and, per parent, where each path last changed. A query reads only that and the viewer's graph, so neither an answer nor its cost depends on anything hidden.
* **Blame walks a file's versions.** A request answers from a kept blame of its version; otherwise it starts or joins that version's **blame job** (one per view key, version and `follow` across servers, by a lease row: a job computes only while it holds the lease, and stops once a renewal fails; at most 2 computing per server, handed out in turn by requester, the signed-in person or every caller without an account together, and 256 waiting per requester; at the ceiling of 4,096 a requester's job takes the place of one of whoever has the most waiting) and waits until its deadline, then answers `warming` while the job goes on, as viewer-graph fills do. A job walks and blames in memory, within 64 MiB (everything it holds counted), and keeps the version asked for and checkpoints spaced to about 8 MiB a job, with what an answer shows of every change named (an answer reads one row). A job past the bound records it, unless it or another job of the key kept blames of a path it reached meanwhile (the next job goes on from those), and later requests of that key answer `too_wide` without walking again, until a blame of a path its walk reached is kept. One kept blame takes at most a quarter of its view key's cap (larger answers `too_wide`), and a write never drops what it keeps.
* **Boundary cuts:** a file moved out of a folder the caller cannot read is added for them, its lines are the moving change's, and nothing names the hidden folder; a file moved into it is deleted. A secret is never read: its blame is refused, its history lists entries only.
* **Bounds:** kept blames at most 128 + 128 bytes a line and 768 a change named (paths stored once per project) and 32 MiB a view key (its oldest dropped first; nothing one view key keeps drops another's, so a project keeps at most 32 MiB × its view keys in use, one per distinct access, not per agent: when a project's access changes, what view keys no viewer has kept before it is dropped, kept blames, too-wide records and kept cursors; the viewer graphs' own rows not yet, BUG-1470); plain-text files of at most 1 MiB; 10,000 lines a page; history pages and cursors as the log's (long cursors kept by the server); the 2 s deadline for every request.
* **Beside S13 servers:** a graph row counts as filled only once S14 wrote its file history (`view_graph.files`), so rows an S13 server writes during a rolling restart are filled again, never trusted.

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
### 13.24 S21: PRs and review (built)

Phase-4 design §4.9 and §5.2 (`docs/design/server/phase-4-agent-scale.md`),
product decisions 10, 12 and 14. Code: `crates/veil-server/src/prs/`
(records and routes; `class.rs` visibility classes; `revision.rs` stacks,
patches and risk; `rules.rs` `.veilrules` `[review]`; `threads.rs`
anchors; `review.rs` approvals and the gate), migration
`0017_prs.sql`, `veil_core::hub::pr` (what a reviewer's device signs),
`vl pr` (`crates/vl/src/pr_cmd.rs`). PRs, titles, bodies, threads and
reviews are **plain text behind the server's permissions**, never
encrypted.

| Route (`/v1/projects/{p}/…`) | |
|---|---|
| `GET prs?state=open\|closed\|landed\|all&q=&n=&after=` | the PRs the caller may see, newest first by creation, with their `count`; `q` searches titles and bodies |
| `POST prs {head, onto?, title, body?}` | a PR for the stack from `onto`'s tip (default branch) to `head` (a branch, or an id of the caller's history) |
| `GET prs/{id}` | the PR, its revisions in the caller's ids, the review gate |
| `GET prs/{id}/diff?revision=&change=&stat=` | a revision's diff (base to head) or one change's: S13's `diff` on the caller's projected history |
| `POST prs/{id}/revisions {head}`, `POST prs/{id}/close` | a new revision, close (the author or an admin) |
| `GET prs/{id}/threads?after=`, `POST prs/{id}/threads {body, anchor?}` | a page of threads (on the PR or anchored to lines), each with its first 20 comments; a new thread (answered with that thread) |
| `GET prs/{id}/threads/{t}?after=`, `POST prs/{id}/threads/{t} {body?, state?}` | a page of one thread's comments; a reply or resolve (answered with that thread) |
| `POST prs/{id}/reviews {patch, verdict, body?, signature}` | a verdict, signed by the device |
| `POST prs/{id}/reviews/dismiss {person}` | an admin dismisses a reviewer's requests for changes |
| `POST prs/{id}/land` | the review gate: `not_ready` with the reasons, or, when met, `landing_unavailable` until S17 (below) |

```text
vl pr create REV --title T [--body B] [--onto BRANCH]
vl pr list [--all | --state S] [--search TEXT]
vl pr show ID [--threads]           vl pr diff ID [--revision N] [--change C] [--stat]
vl pr update ID REV                 vl pr close ID
vl pr comment ID -m M [--path P --line N [--end M] [--old] [--change C] | --thread T]
vl pr resolve ID THREAD [--reopen]  vl pr review ID --approve|--request-changes [-m M]
vl pr dismiss ID PERSON             (admins)
vl pr land ID
```

**Who sees a PR: exactly `VISIBILITY.md`.**
* A PR exists only for people who can read **every path any of its
  revisions touched** (each change's own diff against its parent: files,
  and folders that differ with nothing differing below them). There is no
  partial view. For anyone else every route answers `no such PR that you
  can see`, the answer for an id nobody made, from the same statement.
  The PR is left out of their lists, counts and searches.
* **Visibility classes.** The deciding access line of each touched path
  (`""` for a path no line decides: admins only) makes the PR's class.
  A viewer satisfies a class when they may read each line's path. This is
  equivalent to reading every touched path, because the line that decides a
  path also decides its own path (the unit test checks every subset of
  paths for every viewer a policy can tell apart). A list reads the
  project's classes, keeps those the caller satisfies, and reads only
  PRs in them (`prs_by_class`). A class is tied to one set of access
  lines (`policy_key`: their paths, in order; who a line names does not
  matter). When the lines change, every PR's class is computed again from
  its touched paths (`pr_paths`) before any PR answer is given. A PR whose
  class belongs to old lines is visible to nobody until then. **Every write
  of a class is conditional on the inputs it was computed from**
  (BUG-1250): a reclassification updates a row only if its key and its
  revision (the one thing that changes its paths) are still those it read;
  a new revision is a compare-and-swap of the revision, with key and lines
  from one policy. A row that changed meanwhile stays stale (visible to
  nobody) until the next request; the pass goes once over the stale rows in
  id order, so servers that briefly disagree on the lines never chase each
  other's writes.
* **Ids are random** (`pr-` and 8 hex digits, decision 10), so no gaps
  count hidden PRs. Anything that is not such an id is no PR, with the same
  answer.
* **Creating or updating a PR** needs a person of the project. Every path
  the PR touches must be readable by them. To anyone but an admin, every
  refusal of the stack (a path they cannot see, a merge, a change id twice,
  more than 100 changes or 10,000 paths) is the same one ("this cannot be
  a PR of yours: …"), so it names no hidden change and counts no hidden
  path. Like a push's merge across hidden folders (§13.4), it says only
  that the stack does not qualify. Admins are told which reason. "Nothing
  to review" (the revision is already part of the target) is told to
  everyone, as their own history shows it.
* **A new revision that is the same to its maker** (its base and head are,
  in their history, the current ones) is refused as "that is revision N
  already", N in their numbering (BUG-1254). The 100-revision limit is
  stated without a count.

**What a viewer is shown is computed on their projected history** (§13.4,
S13): snapshot ids are theirs, diffs are S13's diffs between them, and a
change of the stack that is not in their history (it changed only an empty
folder they are not shown) is left out. **Revisions are numbered per
viewer.** Consecutive revisions whose base and head are the same in their
history (a rebase over changes of folders they cannot see, with nothing
else changed) are one revision to them. For the same reason lists are
ordered by creation and no "updated" time is shown: nothing hidden makes a
PR move or a revision appear. Risk, file count, patch, threads and reviews
are about paths they may read.

**Revisions follow change ids.** The stack is the head and its first
parents, down to the first one that is an ancestor of the target's tip
(the base). There is at most one parent per change (a merge is refused:
rebase it), no change id twice, at most 100 changes and 10,000 touched
paths over every revision. A new revision keeps the PR's place; its
threads are carried to it: each (change, side, file) is read and diffed
once for all the anchors on it, one file at a time, holding only the
diff's block positions, the new text and where its lines start (about
4 bytes a line beside the text, BUG-1258). At most 64 MiB of text is read
per revision (the rest outdated, in thread order), within the request's
deadline (BUG-1255).

**Threads and anchors** (§7.3). An anchor names a change (by change id), a
file that change changed, a side (`old` is the change's parent, `new` the
change), lines `start..=end` (at most 1,000) of a text file of at most
1 MiB, and the BLAKE3 hash of those lines. On each new revision an open
anchor moves to the same change id's new snapshot. It moves as it is when
that side's file is the same object; otherwise through the diff of the two
versions (lines inside a changed block do not map), and only if the lines
it lands on still hash to the anchor's context. Otherwise the thread is
**outdated**. Anchors name only change ids, paths and line numbers. There
are at most 1,000 threads a PR and 500 comments a thread, of 64 KiB each.
**Answers are paged** (BUG-1253): a listing holds at most 100 threads, each
with its first 20 comments, and about 1 MiB of comment text in all
(`next`, and a thread's `comments_next`). A thread's own page holds up to
500 comments and about 1 MiB. The bound is applied in the query
(BUG-1258): comments are chosen by their size (`octet_length`, index
`pr_comments_by_time`) and only the chosen bodies are read. A new thread
or a reply is answered with that thread only. `vl pr show --threads`
follows the cursors.

**Revised after review cycle 3** (2026-11-08). Three routes in a row
came through checks keyed on things the author chooses: file names, PR
ids, the history's shape. The checks are now keyed on what the author
cannot change:
* **risk:** a short allow-list for low, everything else normal or high;
* **holds:** a request for changes is attached to change ids, not to a PR;
* **rules:** the rules in force are a state recorded at each landing,
  never found by walking history.

**Reviews** (threats 15, 16). A reviewer must see the PR, may write every
path it touches (an admin, or the groups and people the deciding lines
name), and is not its author. The verdict (`approve` or
`request-changes`) is on the current **patch**, a hash of every file change
(change id, path, both entries) of every change of the stack. The device
signs `project ‖ PR ‖ patch ‖ verdict` under the context `hub-pr-review`.
The server checks it with the signed-in device's key and keeps it. Revision
numbers are not signed, since they are per viewer.

**What counts:** each reviewer's latest verdict given on the current patch
(a rebase over unrelated changes keeps approvals; any change to the files
dismisses them), checked again against the reviewer's access at each
answer. The author's verdict never counts. Where the rule says
`people_only` (always for high risk), an agent session's approval does not
count. Agent sessions are S11: the review row records `agent`, and every
session today is a person's.

**A request for changes holds every PR at its paths, whoever opened it**
(BUG-1278, BUG-1323, BUG-1326; decided by the orchestrator under the
owner's delegation, 2026-11-08). It is attached to the paths the PR had
touched when it was given (`pr_holds`: reviewer, path). Neither change ids
(the client's to write) nor the author (a colleague could take the change
over) key it.
* **What it holds:** every PR touching any of those paths: open or
  reopened, this one or a new one, by its author or anyone else.
* **What releases it, for one PR:** only that reviewer's approval of that
  same PR (of its current patch, given after the hold). A new revision of
  that PR is held again until they approve it. An approval of another PR,
  even at the same paths, releases nothing else.
* **What releases it, for every PR:** an admin's dismissal
  (`POST prs/{id}/reviews/dismiss {person}`, `vl pr dismiss ID PERSON`),
  which deletes the reviewer's holds at that PR's paths.
* **Nothing else releases it:** not a new revision, a new PR, new change
  ids, another author, closing, rebasing, or a change of access.
* **When the reviewer loses sight of it:** if a later revision touches a
  path the reviewer cannot read, the PR disappears for them, as any PR
  must, and it stays held. Everyone who sees it is told "<name> asked for
  changes", nothing more of the request, and an admin decides.
* **Stated limits:**
  * a reviewer can hold every PR at those paths, by anyone, until they
    approve each one or an admin dismisses;
  * an admin may dismiss requests on a PR they wrote (admins can force
    `main` anyway);
  * a hold reached from another PR names only the reviewer.

**Reviews in answers are bounded** (pre-existing, fixed with cycle 3).
The gate reads each reviewer's latest verdict without its body, one row
per reviewer, in the query. A PR answer lists at most the 100 latest
reviews, with bodies within 256 KiB, read only once chosen, and says how
many there are.

**Risk** (per revision, from every change's files together) is an
**allow-list for low; everything else is normal** (BUG-1276, BUG-1277).
**It is rated under the rules in force at each answer** (BUG-1424): a
revision keeps the file changes risk reads (path, secret, executable,
regular; `pr_revisions.files`), and every view of its risk (`show`, its
revisions, the list, the gate, S17's landing) rates the current revision
under the rules in force now, so rules the admins land later (a
`high_risk_paths` entry, a dropped `checks_only`, a broken file) reach
every open PR. The stored class is a cache keyed by the rules' risk key
(their `high_risk_paths` and `checks_only`, all the classification
reads), replaced when a view finds other rules in force. `prs::gate` is
the one function every answer about readiness goes through.
Only regular, non-executable files are ever below normal (BUG-1324): a
symbolic link is rated by what it points at, which its name does not say.
* **high:** `.veilpolicy`, `.veilrules`, `CODEOWNERS` anywhere, CI or
  container configuration anywhere (`.ci/`, `.github/`, `.gitlab/`,
  `.gitlab-ci*`, `.circleci/`, `.buildkite/`, `Jenkinsfile`, `.travis.yml`,
  `azure-pipelines.yml`, `docker-compose*`, `compose.y*ml`, …), a
  dependency manifest or lock file (`Cargo.toml`, `Cargo.lock`,
  `package.json`, lock files, `go.mod`, …), a secret (a sealed entry on
  either side), a path under a `high_risk_paths` entry, or more than 1,000
  files;
* **low,** only when there is at least one file (a PR of folders only is
  normal, BUG-1328) and every file is one of these:
  * **documentation:**
    * Markdown, reStructuredText or AsciiDoc, or an image (PNG, JPEG, GIF,
      WebP), under the top-level `docs/` folder. Not inside a dot-folder
      there, and not an instruction file agents execute (`SKILL.md`,
      `CLAUDE.md`, `AGENTS.md`, …);
    * or `README*`, `LICENSE*`, `CHANGELOG*`, `CONTRIBUTING*` at the
      project root (no extension, or a text one);
  * **test source code:** a source file of a programming language (`.rs`,
    `.py`, `.js`, `.ts`, `.rb`, `.java`, `.c`, …) under a `tests/`,
    `test/` or `__tests__/` folder that is not inside a `src/` folder, or
    a Go `*_test.go` anywhere. Never data, fixtures, specifications,
    configuration or Markdown, wherever they sit. Never anything under
    `spec/`, `testdata/` or `fixtures/`, a build file (`conftest.py`,
    `build.rs`, `Makefile`, …), or an executable file;
* **checks-only:** at least one file, and every file under a path the admins list in
  `.veilrules` as `[review] checks_only = ["docs/**", …]` (`*` within a
  name, `**` for any folders, a trailing `/` for everything below). It
  needs checks only, no approval (BUG-1325). Nothing is checks-only by
  default;
* **normal:** everything else, including every other Markdown file (agent
  instructions, prompts, skill references, Markdown inside `src/`).

**Why low needs an approval** (BUG-1325, decided by the orchestrator under
the owner's delegation, 2026-11-08). A list of names can't know what the
project's build runs: VitePress compiles `docs/*.md` to Vue, and a
`postinstall` script runs `test/setup.js`. So low risk is a lower bar, not
none: one approval from someone other than the author, where an agent's
approval counts. Only the admins can make a path need checks only,
because they know their build.

Whitespace changes are rated like any other (BUG-1256). Comment-only
changes are not detected (phase-4 open question 4).

**`.veilrules` `[review]`** (decision 14):

```toml
[review]
low = { approvals = 0 }
normal = { approvals = 1 }
high = { approvals = 1, people_only = true }
high_risk_paths = ["src/auth/", "infra/"]
checks_only = ["docs/**"]
```

* **Two parsers, one file.** S21 parses only `[review]`
  (`prs/rules.rs`, `toml_edit`, already a dependency of `vl`). S17 parses
  its own `[branches.…]`, and neither judges the other's keys.
* **The defaults** (decision 12, as revised for BUG-1325) apply with no
  file:
  * low needs one approval from someone other than the author, an agent's
    counting;
  * normal and high need one person's approval (agents' approvals count
    for low only);
  * nothing is checks-only.

  `people_only` is forced for high.
* **The rules in force are a state recorded at each landing on the default
  branch** (BUG-1279). `pr_review_rules` holds the state and the tip it
  belongs to. The state is one of:
  * `file`: the valid file's text;
  * `absent`: no file, so the defaults apply. A deletion is an admin's
    change like any other, and counts;
  * `strict`: every risk needs one person's approval.
* **When it is recorded.** In the same transaction as the branch's
  compare-and-swap, for a push and for a commit through the API. The
  branch row's lock orders landings, so the states follow landing order
  exactly, across servers.
* **A landing whose file does not parse** keeps the state recorded at the
  tip it moved from, if it is a fast-forward from that tip (the merge of a
  branch made before a stricter file keeps the stricter state). A forced
  move, or a branch with no state recorded at its old tip, gives `strict`
  until a landing with a valid file, or none, records a state. No history
  is walked, and no older file's text is used.
* **A reader** reads the tip and the record **in one statement**
  (BUG-1322). A landing writes both in one transaction, so a reader always
  sees a pair some landing left, and applies the state recorded at the tip.
* **A record that lags the tip** (the branch moved without a landing: an
  admin's tools, a branch written directly) is brought up by the rule of a
  landing:
  * the tip's own valid file, or its absence;
  * for a broken file, the recorded state, only if the record's tip is an
    ancestor of the tip.

  The write is a compare-and-swap on the record's tip as read. **A read
  never writes `strict`**: a broken file with no state to keep is answered
  strict, and the record is left as it is.
* **Warnings** quote the file, which is the admins' (no access line names
  the root), so only admins read them. Others are told the rules "need an
  admin's attention".
* **Who can change it.** Until S17's push check (admins only) is merged, the
  file changes like any root file: only admins, unless an admin wrote an
  access line naming `.veilrules`. S17's landing service must record the
  state in its landing transaction the same way (`prs::record_landing`).

**Landing** is S17's. When the gate is met, `POST prs/{id}/land` answers
`501 landing_unavailable`, and nothing moves. The follow-up, once S17 is
merged, submits the stack to `POST …/land` one change at a time, bottom
first, onto the target, re-checks the gate (`prs::gate`: the rules in
force, the risk rated under them, the approvals) in the same request,
and marks the PR `landed`. **Decided (owner, 2026-11-07): landing onto a protected
branch meets the same review rules whichever way it comes,** `vl pr land`,
`vl land` or a push that lands; otherwise review is bypassable. The landing
service enforces it once S17 merges, and that is part of the follow-up.

**Not built here:** notifications and the event stream (S18; deliver
`pr.*` only after `prs::visible` at delivery), embargoed PRs (S23; the
class has an `embargo` column that is always empty, and a satisfied class
must have none), `vl pr checkout` (fetching a snapshot that no branch
names is S3's client work), and rate limits on PR creation (S24).

#### Threat review

| # | Attacker | Tries | Result | Test (`server_hub::prs`) |
|---|---|---|---|---|
| 1 | Person without access to a folder a PR touches | lists, counts, searches (title and body words), pages, opens, diffs and reads threads of it | the PR is in no list, count or search; every route answers like an id nobody made; no hidden title, path or real snapshot id in any answer | `pr_projection_equivalence` (6 kinds of viewer, 3 seeds × 16 PRs, 1–3 revisions each, anchored threads) |
| 2 | Same | compares what they see of visible PRs with a project built only from their history | every answer (PR, revisions, diffs per revision and per change, threads, anchors) equals the copy's | same (the copy is made from their projected snapshots; the oracle of who sees what is computed from the files) |
| 3 | Same | watches a PR rebased over changes of folders they cannot see | the same revision to them; lists ordered by creation, no "updated" time | same: 6 such cases across the seeds; the harness fails with numbering by real revisions |
| 4 | Same | a later revision touches their hidden folder, then a third drops it | hidden from then on (the union of every revision) | `prs_follow_revisions_and_access_lines` |
| 5 | An admin's access-line change | hides or shows a touched path | hidden or shown at the next request; lists and counts too | same |
| 6 | A reviewer, or someone in their name | forges a signature, signs another verdict, PR or patch, signs with another device | `unauthorized` | `pr_reviews_and_the_gate` |
| 7 | The author | approves their own PR; pushes new files after an approval | refused; the approval is dismissed (patch-bound); a review of the old patch is refused | same |
| 8 | Someone who may read but not write the files | approves a public PR | refused; a reviewer who loses write access stops counting | same |
| 9 | An agent | approves a high-risk PR | counts for normal risk, never where people are required | same (the agent row is written directly until S11) |
| 10 | Anyone on Earth | comments on a public PR | `unauthorized`; a signed-in non-participant is `forbidden` | `pr_hostile_inputs` |
| 11 | Any participant | hostile ids, titles (control characters, 301 characters, two lines), bodies (64 KiB + 1, escapes), searches with `LIKE` syntax, cursors, states, page sizes, thread ids and states, heads (missing, on the target, the root) | refused cleanly, or matched literally; malformed ids answer like missing ones | `pr_hostile_inputs` |
| 12 | Same | anchors out of range, reversed, zero, 5,000 lines, on a file the change did not change, on a folder, a bad side, `../` paths | `bad_request` | `pr_anchors_survive_revisions` |
| 13 | A participant | opens a PR from an embargoed change, or one built on it | no such revision (embargo lines are withheld from every viewer until S22) | `pr_rules_from_veilrules` |
| 14 | Same | reads a broken `.veilrules` through PR answers | review gets stricter; the file's text reaches admins only | same |
| 15 | Same | floods threads or comments | at most 1,000 threads a PR, 500 comments a thread, under the PR's row lock | by construction (limits checked in the transaction) |
| 16 | — (a race) | an access-line change, a reclassification and a new revision at once | no class of other paths is ever stored under the current lines (BUG-1250) | `s21_cycle2::class_writes_hold_under_scripted_interleavings` (each interleaving scripted; fails with the guard removed), `s21_adversarial::bug_1250_…` |
| 17 | A member who may write a folder | any change of behaviour rated low: whitespace, a build file, CI, a source or data file in a test-named place, Markdown agents execute or programs include | low is an allow-list: documentation in `docs/` and the root's README-like files, test source code in test folders; everything else normal or high (BUG-1251, 1252, 1256, 1257, 1276, 1277) | `prs::rules::tests::low_is_an_allow_list` (a corpus of layouts), `s21_cycle3::risk_classes_rate_real_layouts`, `bug_1276_…`, `bug_1277_…`, `s21_cycle2::bug_1256_…`, `bug_1257_…` |
| 21 | Any participant | makes a listing or a revision hold far more than it answers | listings read only the bodies they answer; carrying holds one file's positions at a time: +2 MiB for 2,100 comments of 64 KiB (was 139 MiB), +26 MiB for 64 files of 1 MiB (was 729 MiB for 8) (BUG-1258) | `s21_cycle2::bug_1258_…` (two tests, each in a process of its own) |
| 22 | The author, or a colleague | grows the PR past a reviewer's access; closes it and opens the same files again (under new change ids too); opens a second or larger PR of them; takes the change over in a PR of their own; gets the reviewer to approve another PR at the same paths | a request for changes holds every PR at its paths, whoever opened it, released for a PR only by that reviewer's approval of that PR or for all by an admin (BUG-1259, 1278, 1323, 1326) | `s21_redesign_cycle2::bug_1326_…`, `a_hold_is_at_its_paths_whoever_opens_the_pr`, `s21_redesign_cycle3::a_hold_given_after_an_approval_holds_that_pr_again`, `a_hold_follows_a_renamed_file`, `s21_redesign::bug_1323_…`, `s21_cycle3::…_holds_until_its_reviewer_or_an_admin_releases_it`, `…_follows_its_change_ids_into_every_pr`, `bug_1278_…` |
| 23 | Anyone who changes the default branch; any PR request | deletes, breaks, merges, fast-forwards or force-moves past a stricter `.veilrules`, lands concurrently on several servers, or reads while a landing commits | the rules in force are the state recorded at each landing; a reader reads tip and record together and never writes `strict` (BUG-1259, BUG-1279, BUG-1322) | `s21_redesign::bug_1322_…` (readers on two servers racing 60 landings, both databases), `s21_cycle3::the_rules_in_force_are_recorded_at_each_landing`, `the_last_valid_rules_hold_across_servers_and_late_records`, `bug_1279_…`, `prs::state::tests` |
| 25 | A member who may read but not write a path | pushes a merge whose first parent is an older snapshot, or first a no-op merge that brings an older snapshot into the history, then a merge taking back an older file; or one push of thousands of merges | a merge is checked against every parent, against their real merge bases (best common ancestors, by the derived graph, found once per pair): a path that keeps one parent's version over another's is a write unless that side made it (BUG-1321, 1327, 1329; push and API commits, `sync::check_changes`); the graph rows of a push's snapshots are kept for the whole push, so its work is linear, and the snapshots read that are not derived yet are bounded (BUG-1425) | `s21_redesign::bug_1321_…`, `s21_redesign_cycle2::bug_1327_…` (both parent orders), `bug_1329_…` (4,000 paths: 49 ms, was 45.7 s), `s21_redesign_cycle3::a_criss_cross_merge_is_judged_against_every_merge_base`, `bug_1425_…` (600 merges: 7.3 s, was 115 s), `s21_c4::a_merge_is_judged_against_a_base_of_the_same_push` |
| 26 | A member who may write a folder | a symbolic link named like documentation or a test; a doc site or install script the build runs; a PR that changes no file; a PR opened under lenient rules, kept open while the admins tighten them | only regular, non-executable files are below normal; low needs one approval by default; checks-only only where the admins list it; a PR of no file is normal (BUG-1324, 1325, 1328); the risk is rated under the rules in force at each answer, never the rules of the revision (BUG-1424) | `s21_redesign::bug_1324_…`, `bug_1325_…`, `checks_only_paths_need_no_approval`, `s21_redesign_cycle2::bug_1328_…`, `prs::rules::tests::checks_only_links_and_the_defaults`, `s21_redesign_cycle3::risk_is_not_lowered_by_renames_or_modes`, `bug_1424_…`, `s21_c4::every_view_of_the_risk_follows_the_rules_in_force` |
| 24 | Anyone who sees a PR | makes its answer read every review's text | reviews read without texts; at most 100 shown, texts within 256 KiB (BUG-1320) | `s21_cycle3::reviews_in_answers_are_bounded` |
| 18 | Any participant | posts many large comments, then has everyone read them | every answer about 1 MiB of comments at most (BUG-1253) | `s21_adversarial::bug_1253_…` |
| 19 | The author of a PR rebased over hidden changes | asks for the revision they are shown | "that is revision 1 already", their numbering (BUG-1254) | `s21_adversarial::bug_1254_…` |
| 20 | Any participant | anchors 1,000 threads, slowing every revision | one diff per (change, side, file); 1,000 threads: 0.65 s (debug), was about 13 min (BUG-1255) | `s21_adversarial::bug_1255_…` (`VEIL_BUG1255_THREADS=1000`) |

**Residual:**
* The first PR request after an access-line change reclassifies every PR
  of the project. Its time grows with all of them, hidden ones included,
  and only admins cause it.
* A list reads every class of the project, including classes only hidden
  PRs use: a few rows, so work grows with their number by microseconds.
* Opening a PR from a stack that holds a change the caller cannot see is
  refused, which says only that (the §13.4 precedent).
* PR creation has no rate limit until S24.

#### Measured

The phase-4 gate (§7: 100,000 PRs in 50 visibility classes; list, count
and search for a restricted viewer under 50 ms; open and update under
100 ms). It is `server_hub::prs::pr_speed` (ignored; release build,
PostgreSQL 17, `bench-quiet.sh`, load 6.0 before and 5.6 after, 2026-11-07).
A dev satisfies 25 of the 50 classes (50,000 PRs); 50 rounds after a
warm-up; open and update are 60 real PRs, each with a new revision:

| | p50 | p99 |
|---|---|---|
| list a page, with the count | 6.1 ms | 18.7 ms |
| search titles and bodies (with the count) | 44.3 ms | 58.0 ms |
| open (`POST prs`) | 10.2 ms | 58.1 ms |
| update (a new revision) | 12.7 ms | 33.0 ms |
| show | 1.5 ms | 2.0 ms |

A list merges one ordered scan of `prs_by_class` per satisfied class and
state, at most a page each. A search reads every PR of the satisfied
classes once (no text index), so its time grows with them: 50,000 is
about the limit for 50 ms. The first measurement, with a sorted list and
two search scans, was 55 ms and 89 ms. After review cycle 1 (one-pass
guarded reclassification, paged threads; load 15.6 before and 18.1 after,
so a little noisy): list 7.7 / 8.3 ms, search 46.1 / 73.1 ms, open
5.6 / 23.7 ms, update 6.7 / 22.7 ms, show 2.5 / 2.9 ms (p50 / p99).

#### Reverting

Revert the merge commit. Migration `0017_prs.sql` only adds tables
(`pr_*`, `prs`); a reverted server never reads them, and they can be
dropped by hand. No format change.

### 13.25 S24, part A: rate limits, request bodies and answers under a budget, bulkheads, shedding, health (built)

Design: `docs/design/server/phase-4-agent-scale.md` §4.11, the S24 row of
§8, threat rows 13 and 20; §4.7 here. Code: `crates/veil-server/src/limits/`
(`mod.rs` the middleware and the per-address connection share, `bucket.rs`
token buckets, `body.rs` request bodies, `answers.rs` answers, `gate.rs`
bulkheads, `health.rs` the metrics); the listener in `lib.rs` (`serve`); one
route and one layer in `api.rs`; the regional cache passes on who its
client is (`cache/mod.rs`, `as_cache`); `vl stats`
(`crates/vl/src/stats_cmd.rs`), and `vl` waits out `retry_after_ms`
(`crates/vl/src/hub.rs`, `Client::send`). Everything is in each server's
memory: no database work per request but the session lookup a route makes
anyway; no migration. Revised by the S24 cycle 1 review (BUG-1330 to
BUG-1339). The landing-specific parts (outstanding landings per agent
session, a person's fair share of a batch, landing counters) come with the
landing service (S17), and per agent session buckets with S11: each agent
session gets its own bucket at `--device-rate`, under a per-person bucket of
ten times it.

```text
veil-server … [--device-rate 200/50000] [--anonymous-rate 20/1000]
              [--max-connections 1024] [--request-memory 512M]
vl stats [--json]
GET /v1/projects/{p}/health        (the project's admins)
```

Every request passes through `limits::admit` before any route, in this order:

1. **Who it counts against.** The device of a session this server knows
   (the session cache, memory only); a bearer token it does not know yet
   (another server's session, a restart, an evicted entry, or not a
   session) is looked up once, as the route would (which caches it for
   both), under the address's own rate of lookups (`--device-rate`): a
   session it finds pays its device, anything else the address
   (BUG-1338). The device of a read grant whose signature verifies (the
   object routes: the `Veil-Grant` header, or a batch's body). Anyone else
   by address (IPv4, or the IPv6 /64). **A regional cache's requests**
   carry the caches' token and its client's address (set by the cache's
   listener, replacing any the client sent): the server counts them
   against the grant's device or that client's address, never the
   cache's (BUG-1332), and its own epoch feed against nobody.
2. **Rate** (token buckets, `bucket.rs`): a burst of `per_second` refilled
   at that rate, within `per_hour` an hour: devices 200/s and 50,000/h (the
   owner's decision: one person's agents share a device until S11; `vl`
   sends about 18 requests a commit, push and pull, BUG-1339), addresses
   without a session 20/s and 1,000/h. Past it, **`429 rate_limited`** with
   `retry_after_ms` (and `Retry-After`): the time until the caller's own
   next token, the same for every project, hidden or not, naming nothing.
   `vl` waits it out (and a `503 busy`'s), at most 8 times and 2 minutes in
   all (BUG-1331). Idle buckets (full ones) are forgotten; a shard keeps at
   most 16,384 keys.
3. **The body, under a memory budget** (`body.rs`, BUG-1187, BUG-1333).
   Every byte of a request body is counted, in KiB, against one of three
   pools of `--request-memory`: **the reserve** (an eighth) for small bodies
   (a declared 1 MiB or less: sign-in, most pushes, fetches), which no large
   body takes; the anonymous pool (a quarter); the signed-in pool (the
   rest). **A body holds what has arrived**: its share grows with its bytes
   (twice them for a body of unknown length), so a head that declares a
   length and sends nothing holds nothing; growth is `503 busy` the moment
   its pool, or its client's part of it, has no more. **One client (device
   or address) holds at most a quarter of each pool**: an anonymous body is
   at most 32 MiB by default; a signed-in body larger than its quarter (a
   large file's upload, up to the route's 2 GiB) grows past it while it is
   all its device holds, up to the whole signed-in pool (and waits up to
   10 s for room there). **A body must keep arriving**: after a 20 s grace,
   16 KiB/s on average (the cache's rule, BUG-1183), at least 8 KiB/s in
   every 20 s window, and it holds at most ten minutes of its last window's
   rate, else `408` and the connection is closed: a client that stops is cut
   off within one window, and a slow one holds in proportion to its rate.
   The share is held until the answer is made. What is left of a body
   refused for its size or its share is read and dropped under the same
   rules (nothing held), so the client reads the refusal.
4. **Bulkheads** (`gate.rs`): a gate per project, then one for the server.
   A project runs at most three quarters of `--db-connections` requests at
   once, the server twice `--db-connections`: **one** flooded project
   leaves the others a quarter of the connections; several at their caps
   can take them all (each still waits only behind its own, and the
   server's gate takes landings first). **Only callers this server already
   knows can see the project wait in its gate** (BUG-1334): a session whose
   permissions for it are cached and current, a grant for it, or anyone on
   Earth for a project with `public` folders; anyone else's request goes
   through the server's gate alone, so its wait and its answer (the
   not-found one) say nothing about the project or how busy it is. Gates
   are keyed by the name as the route decodes it (BUG-1335: `%6C` is `l`),
   and exist only while a request is in or waiting; routes of no project
   share one. A gate has a queue per class and hands a free place to the
   **landings first** (`push`, `changes`, uploads, every other change),
   then pulls and reads, then **search and grep last**, except that a pull
   that has waited 1 s goes before newer landings (a steady stream of
   landings never starves the pulls agents need to land again); a request
   waits at most 20 s, 10 s and 1 s by class (landings, pulls, search), then
   `503 busy` with `retry_after_ms` (0.5–1.5 s, jittered). **Shedding
   order** (design §4.11): search and grep give up first, then **derive
   work** (a derive run waits while requests wait for the server's gate, at
   most 10 s a run, so derived history lags but always progresses), then
   pulls, and landings last.
5. **The route**, its status and its cache hits (tips, permissions) added
   to its project's counts, and **its answer under the answers' budget**
   (`answers.rs`, BUG-1330; the cache's rule since its cycle 3): every
   answer of 64 KiB or more holds a share of a budget of `--request-memory`
   for its bytes until the connection has written them (the share travels
   in the bytes, `Bytes::from_owner`). An answer of known length takes its
   share before its head is sent, waiting at most 2 s, else a read is
   answered `503 busy` and its bytes are let go (a change's answer, the
   change made, goes without a share); a streamed answer takes a share per
   piece, holding nothing while it waits. **An object** (`GET
   /v1/objects/…`, its size known from its tree entry) takes its share
   before it is read, so a refused request reads nothing. One client holds
   at most a quarter of it, except one larger answer alone (up to the whole
   budget).

**The listener** (`serve`): at most `--max-connections` (1,024) open, the
next waiting in the listener's queue; **an address opens at most an eighth
of them** (past that a connection is closed at once), an address being an
IPv4 address or an IPv6 /64, as for the rates (BUG-1336); an address that
sent the caches' token in the last 5 minutes is a regional cache's and has
no share. The TLS handshake and a request's head within 20 s; **a
connection with no request in flight for 20 s is closed**, HTTP/1.1 or
HTTP/2 (BUG-1337: a graceful close, then at once 20 s later; a request is
in flight until its answer's body is done); **answers** must keep up (the
cache's `WriteDeadline`, BUG-1183): a write pending 30 s closes the
connection, and so does one that brings the time writes waited past 30 s
plus a second per 16 KiB written. HTTP/2 is offered with at most 16
streams, a 256 KiB connection window, a 64 KiB stream window and 32 KiB
queued per stream, and pings a connection every 20 s.

**What the server holds, however many requests arrive:** request bodies at
most `--request-memory` (512 MiB), except one signed-in body larger than
its pool, which holds what has arrived while it is read; answers being
written at most as much again, except one larger answer alone; per
connection, its TLS records (about 50 KiB in, 16 KiB out), the HTTP/1.1
buffer (128 KiB) or HTTP/2's windows and queues (at most about 0.8 MiB), so
about 200 KiB for HTTP/1.1 times `--max-connections`: about 0.7 GiB with
the defaults; answers below 64 KiB (one a connection, one a stream); and
the server's caches. Other answers *being built* (a route making its JSON
or frames before its answer is budgeted) are bounded by the gates (at most
twice `--db-connections` requests run at once) and let go at once when
refused; objects, the large ones, are budgeted before they are read.
**Every connection slot comes back in bounded time:** a handshake or head
within 20 s, an idle connection within 40 s, a body that stops within one
20 s window after the grace, a body of `n` bytes within 20 s + `n` /
16 KiB/s, an answer of `n` bytes within 30 s + `n` / 16 KiB/s of a stalled
client, a place in a gate within 20 s.

**Health metrics** (`health.rs`): per project, this server's counts since
it started and over the last whole minute: requests, `429`s, `503`s, `408`s,
tips and permission cache hits and misses, and how many branches' derived
history (S12) is not at their tip (read from the database when asked). **For
the project's admins only:** anyone else who can see the project gets
`403`, someone who cannot gets what a project that does not exist gets, and
anyone on Earth `401`. The answer names no person, device, path or other
project. With several servers each counts what it served.

**Where `vl`'s requests go** (BUG-1339's measurement: 6 agents on one
device, 6 clones and 24 commit, push and pull cycles, 438 requests, about
18 a cycle): `fetch` 114, `tips` 54, `history` 30, `shares` 30, `rings`
(read) 30, ring posts 120 (each push posts all 5 of the project's rings
again), `push` 24, `objects` (uploads) 24, `keys/pending` 6, one ring read
6. For the speed work: a push posting only the rings it changed would save
5 requests a cycle, and a pull fetching in fewer, larger requests some of
the 4.75 fetches a cycle.

**Measured** (`scripts/bench-server.sh limits` through
`bench-quiet.sh`, release builds, PostgreSQL and MinIO, server and agents on
one 32-thread machine; the agents are one device on 127.0.0.1, so the bench
starts the server with the rates and the per-address share out of the way;
the bulkheads and the budget stay). Up-to-date pulls (the tips, from the
server's cache: almost all request path):

| Server | Load (before → after) | Agents | Pulls/s | p50 / p99 (ms) | Server CPU per pull |
|---|---|---:|---:|---|---:|
| S24 | 12 → 111 | 10 | 32,361 | 0.30 / 0.49 | 0.12 ms |
| S24 | | 100 | 49,116 | 1.68 / 6.87 | 0.12 ms |
| `integration` (no limits) | 60 → 162 | 10 | 9,817 | 0.80 / 3.77 | 0.14 ms |
| `integration` | | 100 | 14,089 | 5.77 / 26.2 | 0.13 ms |

The machine was busy for both (the base far more), so throughput and
latency do not compare; server CPU per request, which load moves least, is
the same within noise: **the middleware costs no measurable CPU per
request** (a token, a gate, the body's share). Quiet projects beside a
flooded one (10 agents on 2 projects; a third flooded by closed-loop pulls):

| Server | Flood agents | Flood pulls/s | Quiet pulls/s | Quiet p50 / p99 (ms) |
|---|---:|---:|---:|---|
| S24 | 0 | | 31,993 | 0.31 / 0.48 |
| S24 | 200 | 43,526 | 3,120 | 1.98 / 13.2 |
| S24 | 1,000 | 39,699 | 571 | 12.6 / 73.1 |
| `integration` | 0 | | 21,873 | 0.39 / 1.57 |
| `integration` | 200 | 32,961 | 1,655 | 5.59 / 15.3 |
| `integration` | 1,000 | 29,990 | 310 | 30.5 / 107 |

After the cycle 1 review's fixes (`ab78c65f`; load 29 → 145, so again only
CPU per request compares): up-to-date pulls 2,905/s and 7,673/s at 10 and
100 agents, server CPU 0.15 and 0.13 ms a pull; the quiet projects beside
200 and 1,000 flooding agents p99 20.7 and 52.2 ms. The request path's new
parts (who can see a project, the answers' budget, the idle limit's
counting) cost no measurable CPU either.

These floods are CPU-bound (the tips come from the cache, no database), and
the flooding agents run on the same cores as the server (the load tool used
up to 63 of them): what slows the quiet projects is the machine, which no
bulkhead fixes. Where a flood takes the database, the bulkhead holds it to
its share: in the container test (`a_flooded_project_does_not_starve_a_quiet_one`,
64 clients flooding one project's database reads on a pool of 16), the
flooded project never ran more than 12 requests at once, and the quiet
project's p99 went from 1.1 ms to 1.3 ms.

**Threat review** (design §6 rows 13 and 20, plus this milestone's; the S24
cycle 1 review's findings in rows 13 to 21):

| # | Attacker | Tries | Result | Test (`server_hub::limits`, unit tests in `limits/`) |
|---|---|---|---|---|
| 1 | Anyone on Earth, no session | 8 request bodies of 56 MiB that stop before their end (BUG-1187); any number of them | refused past a quarter of the anonymous pool (32 MiB by default); all of them together hold at most the anonymous pool | `bug_1187_request_bodies_are_buffered_without_a_bound_on_how_many` (8 signed-in uploads beside: the accounting never past 64 MiB; RSS +48 MiB, before +470 MiB); `body::tests::*` |
| 2 | Anyone on Earth | sends a body slowly, or a head and nothing | cut off within a window after the grace, the slot given back | `every_connection_slot_comes_back_in_bounded_time`; `body::tests::slow_bodies_are_cut_off_in_proportion_to_their_rate` |
| 3 | Anyone on Earth, one address | opens every connection | an eighth of them at most; the next closed at once | `every_connection_slot_comes_back_in_bounded_time` |
| 4 | A signed-in device, or an address | floods requests | `429` past its rate; other devices, on the same address too, are served | `past_its_limits_a_client_is_refused_and_told_when_naming_nothing` |
| 5 | Anyone | made-up session tokens or grants, to get fresh buckets | a token not known here is looked up under the address's rate of lookups and, not a session, pays the address; a grant counts for its device only if its signature verifies | same |
| 6 | A refused client | reads its refusal for projects it cannot see, or that do not exist | the same answer, naming nothing but its own wait | same |
| 7 | A runaway agent, or a project's crowd | floods one project | that project runs at most three quarters of the connections; another project's p99 stays put (1.1 ms alone, 1.3 ms beside 64 flooding clients) | `a_flooded_project_does_not_starve_a_quiet_one` |
| 8 | — (overload) | more requests than the server can run | search and grep shed first, derive pauses (at most 10 s a run), pulls next, landings last; a pull that waited 1 s goes before newer landings | `gate::tests::landings_are_let_in_first_and_search_last`, `…::search_is_shed_first_and_landings_last`, `…::a_pull_that_waited_goes_before_newer_landings`, `limits::tests::derive_work_waits_while_the_server_sheds_but_not_for_ever` |
| 9 | A client that goes away while waiting for a place | (a cancelled wait) | its place is never lost: a place handed over just then is given back | `gate::tests::*` (the `Ticket` drop) |
| 10 | A member, someone outside, anyone on Earth | reads a project's health | `403`, the not-found answer for a hidden project, `401`; an admin's answer counts this project's requests only and names nothing | `health_metrics_are_for_admins_only_and_name_nothing_hidden` |
| 11 | A client within its limits | its burst at once, then 40/s; sign-in from one address | never refused | `a_client_within_its_limits_is_never_refused`; `bucket::tests::a_client_within_its_rate_is_never_refused` |
| 12 | Anyone on Earth | floods made-up project names | each name its own gate; the server's gate bounds them all | `gate::tests::idle_gates_are_forgotten` |
| 13 | Someone outside a busy private project | times or counts `busy` for its name against a missing one (BUG-1334) | not in its gate: `404` in about the same time as a missing name | `bug_1334_a_busy_private_project_is_told_apart_from_a_missing_one` |
| 14 | One signed-in person, or four addresses | a slow large upload; heads that declare lengths and send nothing (BUG-1333) | a body holds what has arrived, and only while it keeps arriving; small bodies (sign-in, a small push) have a reserve | `bug_1333_one_slow_large_upload_refuses_every_other_signed_in_body`, `bug_1333_four_addresses_holding_bodies_refuse_every_sign_in`, `a_push_of_one_file_larger_than_the_signed_in_pool_lands`; `body::tests::a_head_without_its_body_holds_nothing`, `…::small_bodies_have_a_reserve` |
| 15 | A member, or anyone on Earth for a public project | names the project in percent-encoded spellings (BUG-1335) | one gate for every spelling | `bug_1335_a_project_named_in_other_spellings_runs_past_its_bulkhead`; `limits::tests::project_names_are_keyed_as_the_route_decodes_them` |
| 16 | One host with an IPv6 /64 | opens connections from many of its addresses (BUG-1336) | one share for the /64 | `limits::tests::the_connection_share_groups_addresses_as_the_rates_do` (`bug_1336_…` needs two global IPv6 addresses of one /64 on the machine) |
| 17 | Anyone on Earth | HTTP/2 connections that answer pings and send nothing (BUG-1337) | closed after 20 s without a request | `bug_1337_an_idle_http2_connection_keeps_its_slot_for_ever` |
| 18 | — (people behind one address) | their first requests to a server new to their sessions (BUG-1338) | each pays its device | `bug_1338_signed_in_people_behind_one_address_are_refused_on_a_server_new_to_them` |
| 19 | — (one person's agents) | 6 agents on one device, cloning, committing, pushing, pulling (BUG-1339) | within the device's rate | `bug_1339_an_agent_fleet_on_one_device_is_refused_at_the_defaults` |
| 20 | — (readers behind a regional cache) | 40 cold reads of one signed-in reader through a cache (BUG-1332) | each counts against the reader's device; the cache's address keeps its own rate | `cache::bug_1332_a_caches_forwarded_reads_count_against_its_address` |
| 21 | Anyone on Earth | 8 clients that ask for a 24 MiB file and never read (BUG-1330) | one answer held at a time for the address; the others `busy` before the object is read (RSS +27 MiB, +196 before) | `bug_1330_answers_to_clients_that_do_not_read_are_not_bounded_by_a_budget`; `answers::tests::*` |
| 22 | A client within its limits, past a burst | `vl` refused `429` or shed `503` (BUG-1331) | waits `retry_after_ms` and tries again | `bug_1331_vl_waits_out_a_rate_limit` |

**Residual:** people behind one address share its anonymous rate and an
eighth of the connections; a person whose access was removed may wait in
the project's gate (not see anything) until this server's cached
permissions are renewed; a grant's device is charged on its verified grant,
not on the request's own signature (a copy of a grant, which only its
device and the caches hold, can spend that device's rate); a body that
arrives fast and then at 8 KiB/s holds what it received for as long as its
rate allows it (ten minutes of it). A bearer token this server does not know
is looked up (one indexed statement) before any gate, at the device rate
per address (BUG-1338): made-up tokens from one address cost the database
ten times what its anonymous rate admits, outside the bulkheads (about 160
addresses at that rate would fill a pool of 32); a token found is cached,
one not found is not (S24 cycle 2 review).

### 13.27 S11: agent sessions, attribution and attempts (built)

Built 2026-11-08 (`crates/veil-server/src/auth.rs` `agent_session`,
`perm.rs` narrowing, `changes.rs` stamping, `sync.rs` attempts;
`veil_core::hub::agent`; migration `0020_agent_sessions`; repository
format 10). Design: phase 2 §5.6, `docs/design/scale/7-agent-attribution.md`.

```text
POST /v1/sessions/agent          (with a person's own session)
{ "project": "acme",
  "attribution": {"agent": "claude-code/2.3", "task"?: "…", "prompt"?: "…", "run"?: "r-41"},
  "only"?: ["src/api/"],         // narrow it to these folders or files
  "seconds"?: 3600 }             // default and most: 12 hours
→ { "token", "project", "person", "expires_at", "only", "attribution" }
```

* **An agent session is not an API key.** It is a row of `sessions` with
  the parent's device and person, `agent` (the attribution, JSON),
  `agent_project`, `agent_only` and `parent_hash`. It is made in one
  statement that reads the parent: only from a live, confirmed person's
  session that is not itself an agent session, and it ends at
  `min(parent's expiry, now + seconds, now + 12 h)`. Removing the device
  ends it with the device's other sessions. Only the token's hash is kept;
  the token is shown once. Its token starts with `agent-`, and its hash is
  a BLAKE3 derived key of its own (`HUB_AGENT_SESSION`), never the plain
  hash a person's session is kept under: a server that predates agent
  sessions never finds one, so it never takes one for its person's own
  session (BUG-1376). `vl session agent [--only PATH…] --agent A
  [--task T] [--prompt-ref R] [--run ID]` prints one for a harness.
* **At most its person, in one project.** Every request is checked as the
  person's (`perm::open`, the same caches and epochs), in its own project
  only (any other answers "not found"). It cannot change access (groups,
  members, managers), devices (vouch, remove), invites, key rings, shares,
  create projects or make sessions (`Caller::person_only`, 403
  `agent_session`): an agent never makes something that outlives its run.
  Nor does it change a file that decides access or review
  (`hub::agent::ACCESS_FILES`: `.veilpolicy`, `.veilrules`, in any folder)
  by any route: its own push or API commit (`View::write`), a merge that
  takes someone else's change of one, or a move of the default branch that
  would accept new access lines (BUG-1377), nor by any branch move whose
  old and new tips differ in such a file, whoever made the change
  (BUG-1391). It never forces a branch move
  or deletes a branch; a narrowed one moves a branch only when the old and
  new tips differ inside its paths alone, else the move is `rejected`,
  naming nothing outside them (BUG-1378). Three rules, each in one place
  every route calls:
  * **Every branch tip an agent session sets** (move, forced move, creation,
    recreation; push, API commit's `onto`, landing) goes through
    `sync::agent_tip`: compared with the old tip's tree. An agent session
    never creates or recreates the default branch, by any route (a push is
    refused first, whatever its snapshots hold; BUG-1538); other new
    branches decide nothing and are allowed. For a narrowed session the
    first question is whether anything outside its paths changes, then the
    files that decide access or review (BUG-1391).
  * **Every write of a narrowed session** decides "anything outside its
    paths?" first and answers one way, naming nothing: a pushed snapshot in
    `sync::narrowing_gate`, before the graft or any other step, where the
    tree it sent must equal, outside its paths, **every** parent's content
    as its person sees it, so it neither writes there nor decides how
    changes there merge (BUG-1539, BUG-1540); an API commit's edits before
    anything is read; a branch tip in `agent_tip` (BUG-1392, BUG-1481).
  * **Every route that takes or returns a path** goes through the
    narrowing: the query routes through `Ask::file_path` (the log through
    `Ask::log_path`: no path is the whole history, its person's); `access`
    refuses an outside path with the same answer; `shares` lists only what
    is inside; `rings` and `rings/{scope}` only the scopes of the secrets
    inside (`Viewer::narrowed_scopes`). Search's scores for a narrowed
    session are computed over its paths alone (BUG-1480, BUG-1536,
    BUG-1537). A test reads the router and fails on any route without a
    class. A new branch removes nothing and
  is allowed.
* **Narrowing applies to files; history is the person's.** `Viewer::only`
  narrows `View::write` (pushes and API commits write only inside), and the
  file routes refuse a path outside: the query API's `tree`, `file`, `show`
  and `diff` (their `path` must be inside), `search` and `grep` (their
  `path` too), and `fetch` (a want is served only inside the narrowing, or
  as the tree of a folder on the way to it; a file at such a folder is
  "not found"). `tips` gives a narrowed session **no grant**: a grant
  reaches everything below its root, wider than the narrowing (per-folder
  grants for the daemon and the workspace socket join S6/S8). `View::key`
  ignores the narrowing: projections, memos and `log`, `history` and
  `ancestry` answers are the person's, so narrowed sessions add no view
  keys. The folders on the way are served as the person sees them (their
  entries' names), never what is below them but the way.
* **The server stamps API commits.** A commit through `POST …/changes` with
  an agent session carries the session's attribution in `Snapshot.agent`,
  inside what the server signs. `ChangeRequest` has no field for one and
  refuses unknown fields, so a caller can neither set nor forge it.
  Pushed snapshots carry what their signer's `vl` recorded (the signer's
  claim, under their device's signature).
* **Attempts on the server.** A pushed snapshot's `attempts` are walked
  like parents: each is completed (grafted, checked, stored) before the
  version that lists it, must be an abandoned snapshot of the same change,
  and is recorded with it (`snapshots` rows, so `fetch` serves its trees).
  Projections project attempts like any version (`project_one`), never
  folded into a parent; `history` sends them with their version; the
  query API's `show` lists them (`attempts`: projected id, reason,
  attribution, the paths changed that the viewer sees). A snapshot whose
  parent is abandoned, a branch whose new tip is one and an API commit
  whose base is one are refused: attempts never land and never enter
  ancestry.
* **Older clients.** Every `vl` request says the newest repository format
  it reads (`veil-format`); one that says nothing reads format 8. `history`,
  the only route that sends snapshots, answers 426 `update_vl` ("update vl
  to 1.2.0 or later") before it would send a format-10 snapshot to a client
  that cannot read it (BUG-1379).
* **Visibility.** Attribution and reasons are plain text inside snapshots,
  projected with them: seen by exactly the people who see the change. A
  change of folders someone cannot see is not in their history, so they
  receive neither. Embargoed merges are refused by the server
  (§11); `vl` withholds an embargoed line with its attribution and
  attempts.

Threat review (phase 2 §6, rows 5 to 7, and what S11 adds):

| # | Attacker | Capability | Harm | Mitigation | Test |
|---|---|---|---|---|---|
| 1 | An agent (or a harness holding its token) | asks for files outside `--only`: `tree`, `file`, `show`, `diff`, `search`, `grep`, `fetch`, a grant | reads more than its task | every file route checks the narrowing first; no grant for a narrowed session | `server_hub` `agents::a_narrowed_session_reads_and_writes_only_inside_its_paths_and_its_history_is_its_persons` |
| 2 | Same | writes outside `--only`, `.veilpolicy` | writes more than its task | `View::write` is narrowed, for pushes and API commits alike | same |
| 3 | Same | makes a session from its session, asks for more than 12 hours, uses it in another project | outlives or widens its person | made only from a person's own live session, in one statement; `LEAST` of the expiries; other projects "not found" | `agents::an_agent_session_comes_from_a_persons_own_session_and_never_outlives_or_widens_it` |
| 4 | Same | vouches a device, invites, adds group members, posts a ring or share, creates a project | a lasting credential or access change | `person_only` on every such route | `agents::an_agent_session_cannot_change_access_devices_invites_rings_shares_or_projects` |
| 4a | An admin's agent session | commits or pushes `.veilpolicy` or `.veilrules`, merges or fast-forwards onto someone else's change of one | changes who has access | `decides_access` in `View::write`, in the merge exception and at the default branch's policy acceptance (BUG-1377) | `agents::an_admins_agent_session_cannot_change_access_through_the_policy_file`, `…never_changes_a_file_that_decides_access_by_any_route` |
| 4b | An admin's agent session, narrowed or not | forces a branch back, deletes one; a narrowed one fast-forwards onto others' work elsewhere | removes or lands content outside its task | no force or delete for agent sessions; narrowed moves compared tip to tip within the narrowing (BUG-1378) | `agents::an_admins_narrowed_agent_session_neither_forces_nor_deletes_a_branch`, `…never_force_or_delete_and_a_narrowed_one_moves_a_branch_only_within_its_paths` |
| 4c | The holder of an agent token, during a rolling upgrade | presents it to a server that predates agent sessions | its person's full session | agent sessions kept under a hash that server never computes (BUG-1376) | `agents::an_agent_sessions_token_is_never_a_full_session_to_a_server_that_predates_it` |
| 5 | The caller of an API commit | sends `agent` in the request | forges attribution | no such field; unknown fields refused; the server stamps the session's | `agents::api_commits_carry_the_sessions_attribution_and_never_the_callers` |
| 6 | A command inside a sandbox | sets `VEIL_AGENT`, writes `.veil-agent`, runs `vl describe` | forges or strips attribution | attribution only from the workspace `vl`'s flags and environment; the sandbox cannot reach the repository | `cli_security` `agent_cli::a_command_inside_the_sandbox_cannot_forge_or_strip_attribution` |
| 7 | A person without access to a change's folders | reads log, show, history, a clone | learns its task, prompt or an attempt's reason | projected with the snapshot; such a change is not in their history | `agents::task_prompt_and_reasons_reach_exactly_who_sees_the_change`; `core_security` `agent_attribution::task_prompt_and_reasons_are_withheld_with_an_embargoed_change` |
| 8 | A hostile pusher | an abandoned snapshot as a tip or a parent; a plain snapshot as an attempt | lands a dead end, or hides history in `attempts` | refused at completion and at the branch move | `agents::attempts_never_land_and_a_valid_one_is_kept_projected_and_shown` |
| 9 | A hostile pusher or server | escapes, overlong fields, 33 attempts, 64 KiB + 1 of reason | corrupts terminals and logs, exhausts storage | `Snapshot::validate_format_10` on every decode and write: the snapshot is `Corrupt` | `agent_attribution::hostile_or_unbounded_attribution_and_attempts_are_corrupt_and_never_written`; `agent_cli::hostile_attribution_in_the_environment_is_refused_without_echoing_it` |
| 10 | — (an older `vl`) | rewrites an attributed snapshot without the field | silent loss, a broken signature | format 10: format-8 builds refuse the repository; format-8 and 9 repositories refuse to store one ("run `vl upgrade`") | `core_format` `format_compat::a_format_8_or_9_repository_refuses_format_10_snapshots_and_upgrades_rewriting_nothing`, `the_format_8_set_upgrades_to_10_and_a_format_8_clone_refuses_attributed_history`, `the_format_10_set_holds_attribution_and_an_attempt` |

**Reverting** S11 is not a plain revert once anything was written: format
10 repositories (every `vl init` and `vl upgrade` from this build) are
refused by older builds, and migration 20 adds four nullable columns,
which an older server ignores; it never finds an agent session (their
hashes are not the ones it computes), so their rows are inert there.

### 13.28 S8: workspaces that fetch on first read (as built)

Milestone S8 of `docs/design/server/phase-2-thin-clients.md` (§4.6, §4.8,
§4.9). Code: `crates/vl/src/mount/fs.rs` (`ReaderView`: a thin clone's
mount), `crates/vl/src/mount.rs` (`for_exec`), `crates/vl/src/sandbox.rs`
(`exec_mounted`, `MidRun`), `crates/vl/src/ws_socket.rs` (new),
`crates/vl/src/confine.rs` (`--private-ports`, `--seed`),
`veil-core` `ObjectStore::entry_shown` and `prefetch` (`promisor.rs`), used
by `vfs/sparse.rs` and the builder's carrying (`builder.rs`). No format,
protocol or server change.

#### The design as built

* **A mount in a thin clone** shows the person's projection (what the
  server gave them) and fetches on first read through S3's promisor:
  * listing and `stat` never fetch a file's content (sizes are in the
    tree); a folder or a plain file not fetched yet is shown without
    fetching it (`entry_shown`), and its object decides when it is read (a
    secret this reader cannot open is `EACCES` then). A file labelled
    secret is decided by its object, fetched to decide. One folder that
    turns out to hold only secrets this reader cannot open lists as empty
    (a checkout would not create it).
  * reading a file fetches its folder's small files (≤ 256 KiB) in the
    same request, once per folder; listing a folder fetches only its tree.
  * the server's refusal hides: `EACCES` at `open` (a thin clone's mount
    fetches at `open`, since the kernel turns any error of a later read
    into `EIO`), and absent from listings and lookups for 10 s; a server
    that cannot be reached is `EIO`, never an absent or empty file. An
    object met under a local change (a workspace's own `@`) and refused at
    the nearest server ancestor whose held tree names it there is the
    server's refusal too (`promisor.rs`, `names_held`).
  * an open file's content is in memory only up to 1 MiB, 64 MiB across
    open files; larger, in an anonymous file (BUG-1365). A file over 1
    MiB is never read whole by the mount: `stat` decides from the first
    bytes of its loose object, and opening, writing into (copy-up) and
    renaming it stream that object to the spill file, checked against its
    id, and on to the upper layer atomically; an unlinked open file is
    written to an anonymous file (BUG-1368). **Outside the bound:** a file a
    thin clone has not fetched arrives whole from the server (an object at
    a time) before it is spilled; a large file the store holds in a pack
    is inflated whole when the mount first looks at it (its first `stat`,
    listing or lookup in the process: BUG-1461, open) and when it is read;
    a sealed secret and a conflicted file are read whole when read;
    recording reads changed files as any snapshot does.
  * a reader that knows an entry's path asks at that path: the mount
    (`read_at`, its folder's prefetch), a checkout and the fallback's
    prefetch (`prefetch_diff_below`, `prefetch_at`) ask for each file at
    its own path, one request a folder, and ask again at a file's other
    paths in the tree they write only if the server refused it at the
    first. So content refused at one path is written where it is readable
    there, wherever it was met first (BUG-1460, BUG-1462, BUG-1463). Every
    other reader that walks a tree or looks a path up and then reads by id
    asks for what it reads at its paths first, a batch a request
    (`tree::prefetch_files`, `prefetch_changes`, `lookup_to_read`;
    BUG-1506): `vl grep`, `diff`, `show`, `cat`, `ls`, `files`, `blame`,
    `log -S`/`-G` and `--follow`, `restore`, `bisect`'s count of unreadable
    files, the attributes a merge reads, rename detection (what its inexact
    pass reads), merges (the files both sides changed) and `split`/`squash`
    by hunk. The locator keeps one place an object, for readers by id only.
    A batch under a local change is asked under its nearest server
    ancestor.
  * **a tree the server refuses is never an error and never silently
    dropped** (decided, BUG-1508). In a thin clone made before its person
    lost access to a folder, the folder's tree is refused once it is not
    held. Readers (`vl show`, `diff`, `log`, `blame`, `grep`, `ls`,
    `files`, the JSON API and `vl serve`) show it as hidden by the path its
    parent already named (`redacted bill/`; `hidden` in `veil.diff/2`; a
    `redacted` directory in `veil.ls`; `hidden_folders` in `vl grep`) and
    nothing inside it, and succeed (`tree::diff_trees_hiding`,
    `walk_files_hiding`). Writers carry a refused folder only one side
    changed by its id without reading it (merge, rebase, the embargo and
    sealing pass of a merge); a checkout leaves it out of the working copy
    (`redacted bill/`), removes what it wrote there, and records it, so the
    builder carries it by id. What the working copy holds there (a file
    the person made, a copy the checkout could not tell as its own) is
    never recorded and never touched, and never silent: `vl status` lists
    it under its own heading, `not_recorded` in `veil.status`, and `vl
    commit` records the rest and names it once (BUG-1528). One both sides
    changed, a path asked for in or above it (`vl restore`, `split`,
    `squash` by path) or a hunk choice that needs it, or a working copy
    folder never left out, is refused by a message naming it and saying the
    person lacks access, and nothing changes (`tree::no_access`); a restore,
    split or squash of other paths keeps it where it is, by id (BUG-1529).
    No writer leaves out or empties it.
  * **the refusal is the server's answer at the place asked, whatever the
    view** (BUG-1530): a snapshot is the server's if the tips reach it or,
    failing that, if the server's history answers for it (it resolves an
    older view's snapshot through the real one); an empty answer under it
    is the refusal (`on_server`, `server_knows`). So a pull after an access
    change leaves a working copy that carries a refused folder working.
  * **access back**: the folder is written whole again. A file the
    left-out checkout kept is compared with the version the folder was left
    from (`Materialised::left`): the checkout's own copy is written over;
    the person's edit is kept as it is and is a conflict in `vl status`
    (`kept_edit` in `veil.status`) while `@`'s parents record exactly the
    version written back: `vl restore PATH` takes that version, and a
    commit of the person's own resolves it (BUG-1531, BUG-1558). Links the
    person makes there are named too (BUG-1559).
  * **after an access change the clone moves to the person's current view
    by itself** (decided, BUG-1509; thin clones). The server names every
    snapshot above a folder the person lost under another id, and serves
    the old ids no more. When a command's reads show it (a refusal under a
    server snapshot, or a page of history that names a snapshot under
    another id: `ObjectStore::current_projection`), when `vl pull` finds a
    tip it had named so, or before a push whose work stands on such a
    snapshot, `vl` moves the clone once, in one operation with a pull
    (`Transaction::move_to_view`, `hub::pull_moving`), reports it in one
    line ("your access changed; moved N changes to your current view"),
    and runs a command again only if the view change made it fail (never
    a `vl ws exec`). A request that fails on the way stops the move with
    nothing changed, a warning, and the next command tries again
    (BUG-1564); before a push it asks only about what the push sends and
    the server's current tips do not reach (BUG-1565), paging in the tips
    it does not hold yet once, as a pull would (BUG-1575). Every server snapshot a
    tag, head or workspace names, or that a change only this clone holds
    stands on, is replaced by its current projection, and each such change
    is rebased onto its parents' (`Repo::rebase_tree`): what the new parent
    no longer names is gone from it, and the server grafts it back on push.
    Nothing below a lost folder is read or written: the paths lost are
    where the old and new parents differ, and a change is compared with
    its parent only there. A change that edited inside one is refused by
    name ("kept where it is: … (it edits bill/, which you no longer have
    access to)") and stays exactly where it is, never rewritten, with every
    change connected to it. Tags, workspaces and heads follow; `vl undo`
    returns the clone exactly to before (and `vl undo`, `redo` and `op`
    never move it). The working copy follows its change: the folder is
    recorded as lost (`Materialised::lost`), what the working copy holds
    there is the person's, never recorded (`vl status`, BUG-1528), and
    when access comes back (another move) the folder is written whole, a
    file left there written over where it is the checkout's own copy (by
    its bytes, `Materialised::own`, without the old version's key) and kept
    as a conflict where it is the person's edit (BUG-1531). What each
    command does in a view that changed (BUG-1508) still holds for the
    command that finds it. **Outside this:** a full clone is not moved
    (BUG-1562), an explicit rebase of a change kept in the old view
    rewrites it with a conflict at the lost folder (BUG-1563), and a
    workspace on a snapshot the clone never fetched is kept in the old
    view, its `vl ws exec` running on no files (BUG-1573).
  * **content already held reads at every path naming it** (decided,
    BUG-1464): removal of access stops new fetches; bytes already on a
    machine stay readable there, at any path naming them, as they are in a
    full clone made before the removal. A path whose content is not held
    is asked of the server at that path (`place_along`): the same content
    refused at one path is fetched at another where it is readable
    (BUG-1367); a refusal hides that path for 10 s, or until something
    makes its bytes held (BUG-1507). Fetching is switched off per thread, never for
    the whole store (BUG-1366).
* **Exact dirty sets:** a mount's recording reuses every unchanged folder
  and file by id and visits only the paths the overlay holds, so it
  fetches nothing; the builder's carrying of what a working copy does not
  show uses the same rule (a deleted file not fetched is a deletion, not
  "unreadable"). A new workspace (`vl ws new`) is marked scanned by the
  current scanner rules, so its first recording does not re-read every file
  (it did: in a thin clone, a fetch of the whole workspace). A re-scan after
  a rules upgrade still reads everything: BUG-1360.
* **`vl ws exec --mount`:** the sandbox is a mount of the workspace (a
  private mountpoint under `$XDG_RUNTIME_DIR`, bound at the project's path
  when confined), started for the run and unmounted after it, or the mount
  `vl ws mount` already serves. Without FUSE (`fuse_available`: the build,
  `/dev/fuse`, `fusermount3`) the run says so and is checked out; in a thin
  clone the sync fetches what it writes first, in batches, and a sparse
  sandbox (`--only`) only its paths (`prefetch_sync`; `SparseView` shows
  what is outside the set without fetching it), so a lost server fails the
  run before the sandbox is touched.
* **The workspace socket** (`ws_socket.rs`, `9-confinement.md` item 17):
  named workspaces' runs, mounted or not, get `$VEIL_WORKSPACE_SOCKET` and
  `vl` first on `PATH`; a `vl` inside forwards its arguments; the `vl`
  outside runs `status`, `diff`, `log`, `show`, `blame` (every revision
  `@` or an ancestor of it, BUG-1361), `commit` (always `--no-advance`,
  BUG-1362), `describe` (of `@`) and `new` (on `@`) as a child of its own
  (`__veil-workspace-command`), with its own environment and hooks off, on
  that workspace only (`Ctx::open_for_workspace`, `Ctx::detached`), after
  recording the sandbox. Everything else is refused before anything opens.
  `--ephemeral` runs get none. Attribution (S11) will come from the same
  `vl` outside.
* **`--private-ports`** and **`--seed SRC:DEST`**: `9-confinement.md` items
  15 and 16. `pasta` only (slirp4netns is not used).

#### Measured (2026-11-08)

`server_hub` `workspaces::s8_bench_ready_to_read` through `bench-quiet.sh`
(the quiet wait ran out: load 64.1 before, 12.0 after, so noisy), a
release `vl`, the test's debug server, PostgreSQL, ext4 NVMe, no Veil
daemon (S6). A thin clone holds `main`; the workspace is on a branch it
never fetched, 100 files a folder.

| Step | 2,000 files | 50,000 files |
|---|---:|---:|
| `vl ws new agent -r feature` | 103 ms | 103 ms |
| `vl ws mount` | 104 ms | 103 ms |
| `ls wide/` (20 / 500 folders) | 21 ms | 31 ms |
| first `cat` (one tree, then the folder's files in one request) | 614 ms | 450 ms |
| **ready, cold** (§4.8: under 2 s) | **841 ms** | **686 ms** |
| **ready, warm** (mounted again; §4.8: under 300 ms) | **104 ms** | **118 ms** |
| read 1,000 files of 10 folders, cold | 5.3 s | 4.6 s |
| `vl ws exec --mount -- cat FILE`, cold / warm | 804 / 103 ms | 1,203 / 103 ms |
| `vl ws exec` checked out (the fallback), first run | 3.8 s | 164 s |

* Ready is independent of the project's size: nothing proportional to the
  files or the history is read before the first `cat`.
* The fallback's numbers are from before its sync fetched in batches
  (`prefetch_sync`: S3's `prefetch_diff`, within `--only`); it then fetched
  one file per request. Two later runs, with batches, ran at load 101 and
  334 to 580 and measured nothing reliable (3,000 files: 60 s, all of it in
  four batch requests to the debug server); to be measured again on a
  quiet machine with a release server, as are the cold reads (each folder
  is two requests to the server, about 230 ms each at that load).

#### Threat review (phase 2's rows 5–7 and 18, and §4.9)

| # | Threat | As built | Test |
|---|---|---|---|
| 1 | a mount shows a file or name its person may not see | the tree is the server's projection; visibility as a checkout's | `server_hub` `workspaces::a_mounted_workspace_shows_exactly_its_persons_projection` (dev and admin; mount, `ws exec --mount`, the fallback; equal to a full clone's checkout; no marker in the clone's objects) |
| 2 | unfetched read as empty or hidden; a refusal read as anything but hidden | `EIO`; a mounted run meets the error; the fallback fails before running; a refusal is `EACCES` at `open`, then absent | `workspaces::an_unreachable_server_is_an_error_in_the_mount_never_a_missing_file`, `workspaces::a_server_refusal_hides_the_file` |
| 3 | `ls -lR`, an indexer: a fetch storm | listing and `stat` fetch no content; folder prefetch only on reads | `workspaces::listing_fetches_no_file_and_reading_one_fetches_its_folder` |
| 4 | a dirty set that misses or adds an edit; recording proportional to the project | the overlay is the dirty set; unchanged by id | `workspaces::recording_a_mount_fetches_nothing_and_holds_exactly_its_edits`, `cli_workspaces` `ws_socket_cli::what_a_mounted_command_changes_is_exactly_what_is_recorded_and_the_same_without_fuse` |
| 5 | the sandbox's `vl` does more than its person may (phase 2, rows 5–7) | the allow-list of commands, its own workspace, the outside `vl`'s identity and environment, no hooks | `ws_socket_cli::*` (6 tests), `workspaces::the_sandboxs_vl_shows_only_what_its_person_may_see` |
| 6 | a run reaches the host's loopback or another run's ports; shares the host's loopback without `pasta` | own network namespace; `pasta` forwards nothing; fails before running | `ports_seed_cli` (5 tests) |
| 7 | a seed is written, or one run sees another's layer; a seed shows what the allow-list masks | overlay on a tmpfs of the run's own; one set of masks for every host path shown | `ports_seed_cli` (6 tests, BUG-1363 and 1364's included) |
| 9 | a mount's memory grows with what is open, outside `--memory` | bounded in memory, the rest in anonymous files | `mount_cli::bug_1365_…`, `mount::fs::tests::large_open_files_are_spilled_and_behave_as_held_ones` |
| 8 | the fallback without FUSE loses a guarantee | the same tests with `VEIL_TEST_NO_FUSE` | in 1, 2 and 4 |

#### Reverting

Revert the merge commit. Nothing on disk changes format; a workspace
created meanwhile keeps its `.veil/local/scanned` marker, which the
reverted `vl` reads as before.

### 13.29 S6: the Veil daemon, a shared object cache (built)

Design: `docs/design/server/phase-2-thin-clients.md` §4.1, §4.3–§4.6, the
S6 row of §9, product decisions 1 (removal at caches within 5 s) and 5
(the daemon runs by default, with an off switch). Code:
`crates/vl/src/daemon/` (`mod.rs` the paths, the client side and `vl
daemon`; `serve.rs` the decision, forwarding and confirmations;
`store.rs` the store; `follow.rs` warm trees; `proto.rs` the socket's
messages). Touched elsewhere, minimally: S3's promisor (`Located::chain`,
the chain where an object was met, from the locator's own walk; the
`thin.rs` promisor asks the daemon first; the thin pull's content fetch
asks it first, `hub.rs`), one server route (`GET /v1/grant-key`), and
`veil-bench daemon`. No migration, no protocol revision, no repository
format.

```text
vl daemon status | start [--cache-size SIZE] | stop
```

* **One per Veil home.** By default one per OS user: the socket in
  `$XDG_RUNTIME_DIR/veil/daemon.sock` (else `~/.cache/veil/daemon/run/`),
  the store and state in `~/.cache/veil/daemon/`; with `VEIL_HOME` set,
  all of it in `$VEIL_HOME/daemon/` (made absolute, and passed so to the
  daemon it starts). The XDG variables count only as the XDG rules allow:
  absolute (an empty or relative one is unset), and `XDG_RUNTIME_DIR` only
  when it is a folder of this user's with mode 0700, else the socket goes
  in the daemon's own folder; `HOME` only when absolute, else the
  account's (BUG-1515). Every directory is made 0700 (a wider one of this
  user's is narrowed; one of another user's is refused), the socket 0600,
  and **both ends check the other's uid** (`SO_PEERCRED`, `getpeereid`): the
  daemon serves only its own user, and a `vl` sends nothing to a socket
  another user listens on (BUG-1515: its signed requests could be
  replayed for ±5 minutes). A lock keeps one daemon per home.
* **On by default** (decision 5): a thin clone's `vl` starts it (`vl
  daemon run`, detached, its errors to `daemon.log`) the first time it
  reads through it, and waits at most 2 s for its socket. **`vl daemon
  stop` is the off switch:** it writes `off`, stops the daemon and `vl`
  starts it no more until `vl daemon start`. The daemon exits when its
  socket is removed or replaced, `off` appears, its Veil home's identity
  is gone, or nobody read or pinned through it for an hour (the next `vl`
  that needs it starts it again, its store as it was). It never makes a
  Veil home: only its own directory, inside one that exists, and below it
  one folder at a time, never their parents (found running the suites: a
  test's home, removed while a daemon started, was made again and the
  daemon ran on, `the_daemon_never_outlives_its_veil_home`; and an object
  kept while its home was removed made it again, BUG-1513).
* **What the design assumes of the machine** (§4.1: "the machine is
  theirs"): one OS user is one person, or people who may read each other's
  files. The store is that user's files, as each clone's `.veil/cache/`
  is; people who must not see each other's files need separate OS users,
  whose daemons share no socket, store or process. Within one OS user every
  request is still checked by its own grant and device signature, which is
  what keeps another Veil home's device, and later a narrower agent
  session (S11), to its own projection through the socket. **Sandboxed
  commands (`vl ws exec`) see neither the socket nor the store**: the
  daemon's folders are Veil's own private folders, listed with the Veil
  home in one place (`ctx::veil_private_dirs`), which the confinement
  never shows: an allowed folder or seed that holds one, as named or
  resolved (`--allow ~/.cache`, `--allow ~`), is refused, naming narrower
  folders to allow, and so is an allowed path inside one (BUG-1512:
  `--allow ~/.cache` showed the store; BUG-1516: a mask covers a folder
  as it is at the start, so one removed and made again during a run
  showed through; refusing by name holds for the whole run). Veil's
  sandboxes never write through a link into one. **Residual
  (BUG-1519):** a second view of a folder that holds them (a bind mount, a
  disk mounted twice, a FUSE mirror such as `bindfs`: made by the person or
  by root, both inside the trust boundary; a confined command cannot make
  one) is not known by name, and an allowed path through it shows them.

#### The decision, per request

The daemon answers the S5 batch (`BatchRequest`, as the client signed it)
for a server and project the request names. It serves an object **from
its store** only if, in this order, nothing looked up before its turn:

1. the grant verifies under the server's grant key, which the daemon
   fetched itself (`GET /v1/grant-key` over the server's TLS as this Veil
   home trusts it), never a key a client sent;
2. the grant is for this project and not expired, and the request is
   signed by the grant's device (`request_signed`, ±5 minutes);
3. the server confirmed the grant's access epochs (its project's and its
   device's person's, for that device) at most 5 s ago and has not
   refused them since;
4. the want's chain starts at the grant's root and each step is an entry
   of a tree in the daemon's store, each tree re-hashed against its id
   (`veil_core::hub::grant::Chains`, the server's own check); only then is
   the object looked up, and it is re-hashed when read.

**Everything else is passed to the server as the client signed it**, with
`skip` naming what the daemon sent itself: no grant key yet, an invalid
grant or signature (the server answers), epochs not confirmed, a tree of
the chain or the object not in the store. What the server sends is
checked against its id and the request's wants, kept (objects of at most
16 MiB) and passed on; a larger one is left out and its reader asks the
server. A refusal ends the answer with its status.

**Confirmations without a session.** The design has daemons poll an epoch
feed, but the daemon holds no session (the feed of S5 needs one) and no
cache token (S9's feed is the server's caches'). So it confirms epochs by
the server's own answers: every request it passes on that the server
answers `200` confirms that grant's epochs at the time it was **sent**
(the server checks the grant's epochs and device before anything else);
and once a second, for each grant read through the daemon in the last 5 s
(`ACTIVE_MS`, kept in memory for 15 minutes), it sends again the latest
request of at most 256 objects signed under it, every object skipped
(`skip` is not signed; the server checks the grant and sends nothing),
while that signature is 30 s inside the server's ±5 minutes. Once nothing
has been read through a grant for 5 s, background renewals stop (zero idle
traffic); when a read arrives for a grant whose confirmation is stale and
the store holds at least one of its wants, the daemon confirms once on
demand before reading its store (using the recorded replay if still inside
the ±5-minute window, or the client's own request with every want in
`skip`, then serving from the store on `200`), so a warm store after idle
costs one small confirmation request instead of re-fetching the objects
(BUG-1680). When a server answers `429` or `503` with `retry_after_ms`,
the daemon sends nothing more on its own account to that server until that
time has passed; reads it cannot confirm meanwhile go to the server as the
client signed them. `401` voids those epochs (a later-sent `200` restores
them); no answer lets them go stale. **So a change committed at time R is
refused by R + 5 s at the latest** (measured: 21–37 ms alone, up to 749 ms
with four suites running at once), and **without the server nothing is
served from the store after 5 s**, public objects included. The replay is
what S5 already allows ("a signed request can be replayed within ±5
minutes by whoever saw it"; the daemon saw it), and returns no object.

#### The client side

* **Thin clones read through it** (S3's promisor): every place the locator
  records now carries its chain (`Located::chain`, `None` where a place was
  not met in trees: a local commit's ancestor or a tip), and a want whose
  chain starts at the root of a grant this process holds (from its pull's
  tips, else one tips request per process) is asked of the daemon first,
  up to 8 requests at once. **Whatever does not arrive is asked of the
  server as before** (S1's `fetch`), so only the server's own refusal is
  ever `Missing`, and a daemon that lies, stalls or is gone changes no
  answer: every object it sends is checked against its id and against
  what was asked, once each, and anything else ends its answer. The thin
  pull (clone and later pulls) fetches each level the same way.
* **Pins.** Each `vl` in a thin clone tells a running daemon (it does not
  start one for this) the trees its workspaces check out and their parents
  (at most 64, by repository id); eviction keeps them and everything below
  them that the store holds (at most 1,000,000 objects marked per
  eviction). Nothing local is ever in the daemon's store: a repository's
  own work stays in its main store (S3), so eviction costs at most a
  second download.
* **Warm trees** (§4.6, "Warm start"). The daemon remembers each project
  read through it (at most 64, for 7 days, `follow.json`) and keeps `vl
  daemon follow` running, a `vl` of the same Veil home (it holds the
  device key and a session; the daemon process never does): once a second
  it asks the server for each followed project's tips (without retrying a
  `429` or `503`, backing off for that server until `retry_after_ms` has
  passed; BUG-1680), and when the default branch's projected root changes,
  reads its trees down to depth 3 (at most 4,000) through the daemon, which
  keeps them. Measured: a new tip's top trees in the store 0.6 s after the
  push returned.

#### Bounds

* **Disk:** `--cache-size` (default 20 GiB or a tenth of the store's file
  system, whichever is less) and at most 500,000 objects; past either, the
  least recently used unpinned objects go, down to 80 %. When what is
  pinned fills it, a new object is not kept (it is still passed on): never
  an eviction loop.
* **Memory:** 64 MiB of budgets: requests 16 MiB (three times a request's
  length, taken before it is read; at most 4 MiB a request), trees read
  for chain checks 16 MiB (three times each tree's length, never waited
  for: past it the rest of the request goes to the server) and answers
  32 MiB (each object held, from the store or the server, from before it
  is read until it is written). A request waits for a pool only while
  holding none of it, and pools are taken in the order requests, trees,
  answers, so waits never cycle. Besides: the index (about 56 bytes an
  object, at most 28 MiB), and per connection its buffers (64 KiB to the
  client, the server's TLS and HTTP buffers, a 64 KiB slice for skipping
  an oversized object), at most 64 connections at once (the next wait in
  the listener's queue). The daemon sets glibc's mmap threshold to 256 KiB
  and at most 4 arenas, so what the budgets free is given back (before:
  325 MiB peak in the test below; after: 69 MiB).
* **Time:** a request within 20 s of connecting, each write within 30 s;
  to the server, connecting within 5 s and each read within 30 s. The
  daemon acknowledges a request as soon as it has read it, then sends a
  progress message every 0.1 s until its answer ends (its store, the
  server and its budgets may each take long). **For the client: any gap of
  more than 0.5 s** (before the acknowledgement or between any two
  messages, pins and status included), **or more than 35 s between whole
  objects (or the answer's end)** whatever progress messages or partial
  bytes arrive meanwhile, **marks the daemon failed for the process**,
  which reads from the server from then on, as it does for an answer that
  ends unfinished, sends what was not asked, or another version (BUG-1514:
  a stalled daemon cost every request a full wait, a small clone 184 s;
  BUG-1518: one that acknowledged and then stalled cost every process
  35 s, `vl status` 36.6 s; now 0.5 s once: a clone 0.9 s, `vl status`
  0.7 s; BUG-1582: one that only sends progress messages or trickles an
  object costs 35 s once instead of holding the process forever).
* **Versions:** every request names the socket protocol's version and every
  acknowledgement the daemon's (`proto::PROTOCOL`, now 1). A daemon serves
  nothing to a request of another version (`426` with its own); a `vl`
  that meets a daemon of another version reads from the server, and stops
  an older one, so the next `vl` starts its own. The stop message is the
  same in every version: empty, it stops any daemon (`vl daemon stop`);
  naming the sender's version, it stops only a daemon of an older one, so
  a stop meant for an older daemon never stops the newer one that
  replaced it meanwhile (BUG-1517).

#### Guarantees and their tests (`server_hub::daemon`)

| # | Guarantee | Test |
|---|---|---|
| 1 | The daemon never serves an object the server would not serve that person's device now: the admin's daemon holds every object; five viewers (anyone on Earth included) asking it with their own grants receive exactly the server's walk, and every real object they do not reach, with every chain they can build (their trees, the admin's real chains, the admin's chains from their root, the admin's root), gets nothing and no store hit; another device's signature, none, a wider root under the signature, a grant signed by the server's identity key, an expired one, one of other epochs, one of another project: nothing from the store; hostile requests refused, the daemon still serving | `the_daemon_serves_only_what_the_server_would` |
| 2 | A person removed from a group, a project whose policy changed, a device an admin removed: refused within 5 s (21–37 ms alone, up to 749 ms under load), never served again | `a_removed_person_or_device_is_refused_at_the_daemon_within_the_bound` |
| 2b | Fails closed: the server cut off, nothing from the store 5 s later (public included), `503`; served again once the server answers | `the_daemon_fails_closed_without_the_server` |
| 2c | Renewals only while reading; warm store after idle; server back-off respected: zero background polls once a grant has not been read for 5 s; a read arriving after idle re-confirms once with a skipped request and serves from the store (or voids on `401` if access changed while idle); on `429`/`503` with `retry_after_ms` the daemon sends nothing on its own account until that time has passed while forwarding unconfirmed client reads as signed | `bug_1680_no_idle_renewals_warm_store_after_idle_and_server_backoff` (BUG-1680) |
| 3 | A thin clone answers eight commands, and checks out the same files, with the daemon off, cold and warm, for the admin and for a person without `billing/`; that person's daemon never held a restricted marker | `a_thin_clone_answers_the_same_with_and_without_the_daemon`; every S3 test (`thin::`, 46) now runs with the daemon on; the core tests check every `Located::chain` agrees with its path (`core_sync` `thin`) |
| 4 | The store keeps to `--cache-size 64K` under 200 files of 4 KiB; memory: 24 readers at once of two 12 MiB files, cold and warm, grow the daemon by less than its budget and their connections' buffers (36–41 MiB measured, alone and four suites at once; held outside the budget, at least 288 MiB) | `the_daemons_store_keeps_to_its_bound`, `the_daemons_memory_stays_within_its_budget`; `daemon::store::tests` (pins kept, a full pin set keeps nothing new, damaged files removed, the index rebuilt) |
| 5 | A `vl` without the daemon works: off is not started again; a daemon killed with `SIGKILL` leaves `vl` working (and is started again); a daemon that answers nothing, or wrong bytes for every object, changes no answer | `vl_works_without_the_daemon` |
| 6 | Its socket and store are its user's alone (0700, 0600; a 0777 directory narrowed); a damaged object in its store is never served | `the_daemons_socket_and_store_are_its_users_alone` |
| — | Warm trees: a new tip's trees to depth 3 in the store with no reader, nothing deeper; a new clone reads them from the store | `the_daemon_keeps_the_top_trees_of_followed_projects_warm` |
| — | It never outlives its Veil home: exits within a second once the identity is gone; in a removed home, `vl daemon run` and `start` refuse and make nothing; nor does keeping an object | `the_daemon_never_outlives_its_veil_home`, `daemon::store::tests::keeping_an_object_never_makes_a_removed_veil_home_again` (BUG-1513) |
| — | A stalled daemon costs a process one wait, before or after its acknowledgement, or when it only reports progress or trickles an object; a `vl` and a daemon of other versions agree, and a stop never reaches a newer daemon | `a_stalled_daemon_costs_a_vl_at_most_one_wait` (BUG-1514), `s6r2_a_daemon_that_stalls_after_its_acknowledgement_costs_a_vl_one_short_wait` (BUG-1518), `s6r3_a_daemon_that_only_reports_progress_costs_a_vl_one_short_wait`, `s6r3_a_daemon_that_trickles_an_object_costs_a_vl_one_short_wait` (BUG-1582), `a_vl_and_a_daemon_of_other_versions_agree`, `s6r2_stopping_an_older_daemon_never_stops_the_one_that_replaced_it` (BUG-1517) |
| — | The daemon's place follows the XDG rules; a `vl` asks only its own user's daemon | `s6r2_an_empty_xdg_variable_never_puts_the_daemon_where_vl_runs`; `s6r2_a_vl_never_asks_another_os_users_daemon` (needs root) (BUG-1515) |

#### Threat review (design §6 rows 1–5, 8, 9, 14, 15, 18, plus this milestone's)

| # | Attacker | Tries | Result | Test |
|---|---|---|---|---|
| 1 | A person without access to a folder, on the same OS user (another Veil home) | asks the daemon, which holds every object, for every real id with every chain | nothing; the server's own answers for what forwards | guarantee 1 |
| 2 | Same | a real grant with a chain through another snapshot's or the admin's trees | chains start at the grant's root, each step from the hash-checked store | guarantee 1 |
| 3 | A same-user process | hands the daemon its own grant key and a grant it signed | no such field: the daemon checks under the key it fetched from the server | by construction; guarantee 1 (a grant signed by another key) |
| 4 | A person or device removed | keeps using a grant | refused within 5 s | guarantee 2 |
| 5 | A sandboxed agent (`vl ws exec`) | connects to the socket, reads the store, also through an allowed folder that holds them (`--allow ~/.cache`), or after the folder is removed and made again during the run | an allowed folder or seed holding one of Veil's folders is refused, so none is ever shown (BUG-1512, BUG-1516); a second view made by the person or by root (both inside the trust boundary; a confined command cannot make one) is residual (BUG-1519); without the device key it could not sign a request anyway | `cli_workspaces` `confine_cli::the_daemons_store_and_socket_stay_hidden_when_an_allowed_folder_holds_them`, `s6r2_the_daemons_folders_stay_hidden_by_every_route`, `s6r2_a_daemon_folder_made_again_during_a_run_stays_hidden`, `s6r3_a_linked_home_and_unusual_xdg_values_never_show_or_misplace_the_daemon` (a `HOME` through a link; a relative `XDG_CACHE_HOME`; an `XDG_RUNTIME_DIR` not this user's 0700 folder) |
| 5b | Another OS user | listens first at the daemon's socket path (a shared `XDG_RUNTIME_DIR`) | a `vl` checks its peer's uid and sends nothing; a runtime folder not this user's 0700 one is not used (BUG-1515) | `s6r2_a_vl_never_asks_another_os_users_daemon` (needs root) |
| 6 | Another OS user | connects to the socket, reads the store | the directories are 0700 and the peer's uid is checked | guarantee 6 (modes; a second uid needs root to test) |
| 7 | A local process, a torn write | changes bytes in the store | the object fails its id check, is removed, comes from the server | guarantee 6, `store::tests` |
| 8 | A lying or broken daemon (a same-user process on its socket) | answers nothing, wrong bytes, another object, one object without end; or acknowledges and then only reports progress, or trickles an object | the client checks each object's id, that it was asked for and arrives once, and bounds both each gap (0.5 s) and the time between whole objects or the end (35 s); past either, the daemon is not asked again by the process and the rest comes from the server (BUG-1514, BUG-1518, BUG-1582) | guarantee 5; `s6r3_a_daemon_that_only_reports_progress_costs_a_vl_one_short_wait`, `s6r3_a_daemon_that_trickles_an_object_costs_a_vl_one_short_wait` |
| 9 | The partitioned daemon | serves after the server is gone | nothing from the store 5 s after its last confirmation | guarantee 2b |
| 10 | A same-user process | floods the socket (64 connections, 4 MiB requests, stalls) | budgets and time limits; same-user processes can stop the daemon anyway (it is theirs) | guarantee 4 |
| 11 | Hostile input | bad JSON, unknown ops, a project or server name with `/` or `..`, 10⁵+1 wants, 65 pins, junk on the socket | refused cleanly; still serving | guarantee 1 |
| 12 | Anyone on Earth | times the daemon | as at a regional cache (design row 14): only objects the asker may read are looked up; residual accepted | by construction |

**Residual:** the daemon passes requests it cannot decide to the server,
so a same-user process can make it send requests to any HTTPS server it
names (each with its own store namespace, by server and project); it can
do the same itself. A grant voided by an access change is served from the
store for up to one renewal after the change (about a second, 5 s at the
most). Concurrent cold reads of one object are not coalesced (S9's are):
each forwards, and later readers find it in the store.

#### Measured

`bash ~/.cache/veil-orch/bench-quiet.sh scripts/bench-server.sh daemon`
(2026-11-08, release builds, PostgreSQL and MinIO, server, daemon and
clients on one 32-thread machine; load 16.0 before, 91.9 after: the
machine filled during the run, so the clone times are noisy). Medians of 5.
"Workspace ready" is §4.8 rows 1–2: the tips and grant from the server,
then the root and every top-level tree (11 and 101 trees); the FUSE mount
(10–50 ms) is S8's. "Warm" is the daemon after one clone read the project.

| Files | Case | No daemon | Cold daemon | Warm daemon | Target (warm) |
|---:|---|---:|---:|---:|---:|
| 1,000 | workspace ready | 3.4 ms | 5.1 ms | **1.5 ms** | 300 ms |
| 10,000 | workspace ready | 4.5 ms | 7.8 ms | **2.3 ms** | 300 ms |
| 1,000 | thin clone (every tree and file) | 193 ms | 435 ms | 196 ms | |
| 10,000 | thin clone (every tree and file) | 813 ms | 824 ms | 713 ms | |

* The warm target is met by two orders of magnitude: the trees come from
  the daemon's disk, and only the tips request reaches the server.
* A cold daemon costs a second hop (the client to the daemon, the daemon to
  the server) and the start of the daemon itself: at 1,000 files the first
  clone takes about twice as long; at 10,000 the hop is lost in the
  transfer.
* After the run the daemon had served 83.5 % of objects from its store.

#### Not built in S6 (and why)

* The file watcher (S7) and mounts (S8) use this process and socket
  later; nothing of either is here.
* Coalescing concurrent cold reads of one object, and decoded trees cached
  across requests: not needed for the guarantees; to measure first.
* "Every tree read in the last day" in the warm set (§4.6): the depth-3
  set only; the LRU store keeps recently read trees anyway.
* `vl doctor` does not report the daemon yet (`vl daemon status` does).

#### Reverting

Revert the merge commit. Nothing persistent changes format: thin clones
are unchanged, the daemon's store is a cache (delete `~/.cache/veil/daemon`
or `$VEIL_HOME/daemon`), and the server's `GET /v1/grant-key` is additive.
Stop running daemons first (`vl daemon stop`), or they exit when their
socket is removed.

### 13.30 S18: content merges, conflict reports and the event stream (as built)

Milestone S18 of `docs/design/server/phase-4-agent-scale.md` (§4.3, §5.1–5.2,
§6, §8): content merges by worker pool, bounded re-queue (`merges` in
`0022_landing_merge.sql`), visibility-redacted conflict reports, and the
project event stream (`GET /v1/projects/{p}/events`). Code:
`crates/veil-server/src/landing/merge.rs`, `crates/veil-server/src/events.rs`,
and `crates/veil-core/src/hub/land.rs`.

#### The design as built

* **Merge workers (`landing/merge.rs`):** when a queued change cannot take
  S17's fast path (`edits::fast_path`), `merge::can_merge` checks whether the
  entry has `merges < MAX_MERGES` (`3`) and its overlapping paths can all be
  content-merged cleanly:
  * **Visibility gate first:** every path of the change must be readable and
    writable by the submitter, and every overlapping edit on the branch since
    the base (`paths_overlap`) must also be readable by the submitter. A
    submission touching `.veilpolicy` or `.veilrules`, an already-merged commit
    (`parents.len() > 1`), or a path failing the visibility gate is never handed
    to a merge worker.
  * **State transition (`queued -> merging`):** the batch's commit transitions
    eligible rows to `state = 'merging'` inside the batch transaction (guarded
    by `AND state = 'queued'`) and only spawns a background merge worker on a
    bounded semaphore (`MAX_WORKERS = 8`) after the batch commits.
  * **3-way content merge (`run_worker` / `merge_stack`):** the worker reads the
    submitter's current access epochs from `access_epochs` and the tip's
    `.veilpolicy`, verifies the submitter may still read and write every edit of
    the change whole on both the current view and the tip's policy (refusing
    without naming any hidden path if access changed), loads `.veilattributes`
    from the tip (`ServerAttrSource`, restricted to public regular files the
    submitter may read), and runs a 3-way merge per overlapping path
    (`merge_entry_bytes`):
    * paths matched by `-merge` or `binary` (`MergeAttr::Binary`) in
      `.veilattributes`, binary blobs (`looks_binary`), non-files, non-`Public`
      entries, or newly added files with different content (unless `merge=union`)
      fail the content merge and produce a conflict report;
    * paths matched by `merge=union` (`MergeAttr::Union`) merge via
      `veil_core::attributes::union_merge`;
    * all other plain-text files merge via `veil_core::textmerge::merge`.
  * **Landing check, push re-check and re-queue (`merging -> queued`):** when
    every overlapping path merges cleanly, the worker applies the merged edit set
    to the tip tree (`edits::apply`), verifies the landing check
    (`edits::same_edits`) and whole-change visibility on the resulting diff,
    signs the new snapshot (recording the prior submitted snapshot IDs in
    `predecessors`), runs `service::recheck_merged` (`sync::complete` on the new
    parent), stores the objects, and atomically updates the queue row
    (`SET state = 'queued', stack = $4, merges = merges + 1, created_at = …
    WHERE project_id = $1 AND branch = $2 AND seq = $3 AND state = 'merging'
    AND merges < $5`), emits a `land.requeued` event on the submitter's stream,
    and wakes the branch's landing service. At most `MAX_MERGES` (`3`) merge
    passes run per ticket; a fourth overlap finishes as `conflict`.
* **Conflict reports (`ConflictReport`, `ConflictReport::into_result`):** when
  `can_merge` is false or a merge worker finds an unmergeable overlap,
  `merge::build_conflict` builds a visibility-checked report (which
  `landing::seen` then projects for the caller):
  * **Hidden-path redaction:** if any overlapping path of the submission or any
    overlapping change on the branch (`paths_overlap`) is not readable by the
    submitter (`hidden = true`), the report collapses to
    `message: Some("conflicts with changes you can't see")` (`HIDDEN_CONFLICT`),
    `paths: []`, `conflicts: []`, and `landed_since: []` (with `onto` and `base`
    projected for the submitter by `landing::seen`). No hidden path, name,
    count, or content is ever placed in the database outcome, HTTP response, or
    event stream.
  * **Visible conflict details:** when every overlapping path is readable by the
    submitter, the report populates `paths`, `onto` (projected tip), `base`
    (projected base), `conflicts` (`Vec<ConflictPath { path, base, main, yours }>`
    with public file object IDs from the base, tip, and submitted edits), and
    `landed_since` (`collect_landed_since`: up to 256 first-parent commits on
    the branch since the base that touched the overlapping paths and have at
    least one readable edit, projected for the submitter by `landing::seen` so
    commits touching only hidden paths are omitted).
* **The event stream (`GET /v1/projects/{p}/events`, `events.rs`):** an SSE
  (`text/event-stream`) endpoint for signed-in project participants (with
  optional `?ticket=`, `?branch=`, and `?types=` filters):
  * **Events:** `land.requeued`, `land.landed`, `land.conflict`, and
    `land.rejected` are routed only to streams owned by that ticket's
    submitter (`emit_ticket`), passing the outcome through `landing::seen` for
    the receiver's current view; `main.moved` is broadcast to connected project
    streams (`emit_moved`), projecting `(old_tip, new_tip)` and the batch's
    snapshots per viewer and skipping any viewer for whom `p_old == Some(p_new)`
    (a move whose edits were entirely in paths hidden from that viewer). Every
    emission reads current access epochs (`caches::read_epochs`) before
    opening the subscriber's `Viewer`, so permission revocations take effect on
    the very next emitted event and never populate the viewer cache with stale
    zero epochs.
  * **Bounds per connection and per person:** each `(ip, device_key)` connection
    key may hold at most `MAX_STREAMS_PER_CONNECTION` (`8`) concurrent streams,
    and each person may hold at most `MAX_STREAMS_PER_PERSON` (`8`) concurrent
    streams; a 9th open returns `429 Too Many Requests` (`rate_limited`).
    `StreamBody::drop` calls `Events::evict` to release the slot when closed.
  * **Slow or absent readers evicted immediately:** each stream holds an
    in-memory queue (`SubQueue`) of at most `MAX_QUEUE_PER_STREAM` (`64`) frames
    and at most `MAX_BYTES_PER_STREAM` (`64 KiB`), tracked in `total_bytes`
    (`Events::held_bytes`). `push_frame` checks both bounds before queueing; if
    a reader's queue is full or would exceed `64 KiB`, `Events::evict` removes
    the subscriber, clears and shrinks its frame buffer, decrements `total_bytes`
    to zero, and marks the stream closed without blocking landing or merge
    workers.
* **Agent sessions across queuing, content merges, conflict reports and events
  (BUG-1685):** `landing_queue.agent_session` (`0022_landing_merge.sql`) records
  the submitting agent session's `token_hash`. `service::prepare`,
  `service::commit`, `merge::run_worker`, and `events::emit_ticket` /
  `events::emit_moved` reload and verify the session via
  `auth::load_agent_session` (checking that the session, its parent session, and
  its device have not expired or been revoked), rejecting or evicting at once if
  gone; `merge::merge_stack` and `service::entry` enforce `sync::agent_tip` and
  `veil_core::hub::agent::decides_access` on every original and merged snapshot
  against the base it lands on while preserving `agent` attribution and
  `attempts`; and `merge::build_conflict`, `merge::collect_landed_since`, and
  `landing::seen` require `view.within_narrowing(path)` so a narrowed session's
  conflict reports and SSE events name nothing outside its paths.

#### Threat review (phase 4 §6 and S18 guarantees)

| # | Threat | Mitigation | Test |
|---|---|---|---|
| 1 | A content merge lands a change whose submitter cannot see every edit whole | `merge_stack` checks read/write access on current permissions and the tip's `.veilpolicy` before and after applying the merged edit set, and runs `recheck_merged` (`sync::complete`) | `server_hub` `landing::a_merge_never_lands_anything_its_submitter_could_not_see_whole` |
| 2 | A conflict report or SSE event leaks a hidden path, name, count, file ID, or hidden commit on `main` | Any unreadable overlapping edit sets `hidden = true`, collapsing the report to `"conflicts with changes you can't see"` with empty `paths`, `conflicts`, and `landed_since`; `main.moved` skips viewers whose projection did not change | `server_hub` `landing::no_event_or_report_reveals_hidden_paths_names_counts_or_content` |
| 3 | A re-queued change lands twice under concurrent workers or batches | State transitions (`queued -> merging -> queued -> landed`) are guarded by atomic `WHERE state = …` clauses in Postgres; `predecessors` and `landings` record the pre-merge snapshot IDs in the branch lineage | `server_hub` `landing::a_requeued_change_lands_at_most_once` |
| 4 | A client opens unbounded SSE streams to exhaust file descriptors or hub slots | `MAX_STREAMS_PER_CONNECTION = 8` and `MAX_STREAMS_PER_PERSON = 8` enforced atomically on open; `StreamBody::drop` evicts on close | `server_hub` `landing::the_event_stream_is_bounded_per_connection_and_per_person` |
| 5 | A slow or stalled SSE reader buffers unbounded events in server memory | Per-stream queue bounded at 64 frames and 64 KiB (`MAX_BYTES_PER_STREAM`); overflow calls `Events::evict` immediately on emit and frees held bytes to 0 | `server_hub` `landing::a_slow_or_absent_reader_never_holds_server_memory` |
| 6 | Repeatedly conflicting changes loop between the queue and merge workers forever, or ignore `.veilattributes` | `merges` column capped at `MAX_MERGES = 3`; `.veilattributes` (`merge=union`, `-merge`, `binary`) loaded from the tip via `ServerAttrSource` and honoured by workers | `server_hub` `landing::merge_attempts_cap_at_three_and_veilattributes_govern_content_merge` |
| 7 | A queued or re-queued agent-session change escapes its session narrowing, touches an access/review file, lands after the session is revoked, loses its attribution/attempts on content merge, or learns paths outside its narrowing via conflict reports or SSE events (BUG-1685) | `landing_queue.agent_session` persisted and verified at prepare, merge, re-queue, and commit (`auth::load_agent_session`); `merge_stack` and `service::entry` enforce `sync::agent_tip` and `decides_access` and preserve `agent`/`attempts`; `build_conflict`, `collect_landed_since`, and `landing::seen` redact anything outside `within_narrowing` | `server_hub` `landing::a_narrowed_agent_sessions_change_that_needs_a_content_merge_lands_within_its_paths`, `landing::a_narrowed_agent_sessions_change_whose_merge_touches_outside_its_paths_or_an_access_file_is_refused`, `landing::a_session_revoked_while_its_change_waits_in_the_queue_never_lands`, `landing::a_landed_merged_snapshot_keeps_the_sessions_attribution_and_attempts`, `landing::a_narrowed_sessions_events_and_conflict_reports_name_nothing_outside_its_paths` |

### 13.33 S7: the Veil daemon's file watcher (built)

Design: `docs/design/server/phase-2-thin-clients.md` §4.7, the S7 row of §9,
and product decision 5 (the daemon runs by default and watches working
copies, with `vl daemon stop` and `watch = false` in `.veil/local/config.toml`
or `$VEIL_HOME/config.toml` as off switches). Code: `crates/vl/src/daemon/watch.rs`
(the watcher, `openat(..., O_NOFOLLOW | O_DIRECTORY)` tree walk, inotify
event draining, tokens and bounds), `crates/vl/src/daemon/{mod,proto,serve}.rs`
(`Request::Watch`, `config.toml` `watch` settings, `vl daemon status`),
`crates/vl/src/doctor.rs`, `crates/vl/src/ctx.rs` (watcher queries in
`record_once` and full-scan fallback for `vl ls --all`), and
`crates/veil-core/src/{builder,statcache,working_copy,workspace}.rs`
(`WatchPlan`, `build_tree_watched`, partial `StatCache` updates, and
`WatchRecord` in `.veil/local/checkout.json`). `veil-core` stays portable to
`wasm32-unknown-unknown`.

* **Advisory, never authoritative.** The watcher only narrows which
  directories `build_tree_watched` opens and lists; every inspected path
  still goes through the stat cache, racy-mtime window, secret scanner and
  sealing checks (`verify_sealing`, `protect_moves`). Directories that
  produced warnings, quarantined/isolated files or held-back edits in the
  previous snapshot are recorded in `checkout.json` (`WatchRecord::recheck`)
  and re-inspected on the next build so `BuildReport` and `vl status` match
  a full scan.
* **When the watcher cannot vouch, `vl` scans.** The daemon answers
  `known: false` on the first command in a working copy, after a daemon
  restart or working-copy move (`st_dev`/`st_ino` mismatch), on an unknown
  or stale token, on kernel queue overflow (`IN_Q_OVERFLOW`) or unmount
  (`IN_UNMOUNT`), when `.veilpolicy` or `.veilattributes` is modified, or
  when a directory or dirty-path bound is exceeded. `vl` also bypasses the
  watcher plan whenever `.veilpolicy` or keys changed, an unaccepted policy
  guards the working copy, or a command rewrites the working copy (`vl
  restore`, `vl ws switch`, `vl renormalize`, `vl ls --all`).
* **Confined to the working copy.** Every watched directory is opened step
  by step from the working copy root with `openat(..., O_RDONLY |
  O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)`, verified with `fstat` to belong
  to the OS user (`st_uid == geteuid()`) and stay on the root filesystem
  (`st_dev == root_dev`), checked not to hold `.veil`, and registered via
  `/proc/self/fd/{fd}`. Symlinks and mount boundaries are never followed.
* **Bounded.** One daemon watches at most 64 working copies (LRU-evicted);
  each working copy watches at most `max_dirs` directories (default 65,536)
  and buffers at most `max_dirty_paths` dirty paths (default 16,384) and
  1 MiB of path strings. Past any bound, the working copy's watches are
  dropped, the daemon returns a notice, and `vl` warns and falls back to
  full scanning.

#### Guarantees and tests (`crates/vl/tests/cli_basic/working_copy_cli.rs`)

| # | Guarantee | Test |
|---|---|---|
| 1 | `vl status` and `vl commit` give the exact same answer with the watcher as with a full scan across edits, adds, deletes, renames, mode changes, racy-window commits, daemon restarts, tampered tokens, and `.veilpolicy` edits | `working_copy_cli::s7_watcher::s7_g1_status_and_commit_with_watcher_match_full_scan_across_all_changes_and_restarts` |
| 2 | Never reads or reports anything outside the working copy, never follows symlinks out of it, and never descends into nested `.veil` repositories | `working_copy_cli::s7_watcher::s7_g2_watcher_never_follows_symlinks_or_escapes_working_copy`, `s7_hostile_watch_inputs_never_escape_or_crash_daemon` |
| 3 | Bounded watched directories and dirty paths per working copy; past them it drops watches, warns, and falls back to scanning | `working_copy_cli::s7_watcher::s7_g3_watcher_bounds_fall_back_to_scanning_and_warn` |
| 4 | Off when the daemon is stopped (`vl daemon stop`) or `watch = false` in `config.toml`, and `vl` works identically without it | `working_copy_cli::s7_watcher::s7_g4_watcher_is_off_when_daemon_stopped_or_disabled_in_config` |
| 5 | Secret files (`.env.*`) are sealed and secret leaks in plain files are quarantined on commit with the watcher active exactly as with a scan | `working_copy_cli::s7_watcher::s7_g5_secrets_are_sealed_and_leaks_quarantined_with_watcher` |

#### Measured (20,500 files, 1,202 directories)

`bash ~/.cache/veil-orch/bench-quiet.sh cargo test --release -p vl --test cli_bench -- --ignored --nocapture bench_status::status_on_20k_files`
(release build, 10 runs each, machine load 14.77 before, 14.95 after):

| Case (20,500 files) | Without watcher (scan) | With watcher (daemon) | Speedup |
|---|---:|---:|---:|
| `vl status`, unchanged tree | 41.3 ms (min 29.5) | **11.0 ms** (min 10.1) | **3.8×** |
| `vl status`, 1 public file edited | 48.1 ms (min 41.7) | **27.2 ms** (min 14.8) | **1.8×** |
| `vl status`, 1 restricted file edited | 54.7 ms (min 42.8) | **25.6 ms** (min 17.4) | **2.1×** |
| `vl commit`, 1 public file edited | 54.6 ms (min 47.6) | **32.5 ms** (min 19.9) | **1.7×** |

#### Reverting

Revert the merge commit. The `watch` field in `.veil/local/checkout.json` is
optional (`#[serde(default)]`) and ignored by older `vl` builds; `Request::Watch`
is additive on the daemon socket.

---

### 13.35 S19: CI through the API, land first / test after, and `main@tested`

Design: [`docs/design/server/phase-4-agent-scale.md`](design/server/phase-4-agent-scale.md)
§4.6 ("CI through the API, not through a clone"), §4.7 ("Agents start from
`main@tested`"), §5.2 ("Checks, after landing"), §6 Threat 10 ("A compromised
CI runner").

#### What it builds

* **Migration `0025_ci_and_tested.sql`** (version 25):
  * `sessions.agent_runner BOOLEAN NOT NULL DEFAULT FALSE`: marks a session
    as a narrow CI runner session.
  * `checks (project_id, snapshot, name, state, summary, url, log, runner_id, runner_name, session_paths, admin_only, updated_at)`,
    primary key `(project_id, snapshot, name)` with index `checks_by_runner
    (runner_name, updated_at)`.
  * `tested (project_id, branch, lineage, snapshot, depth, updated_at)`,
    primary key `(project_id, branch)`.
* **`.veilrules` check configuration (`crates/veil-server/src/landing/rules.rs`):**
  * `[branches.<name>] required_checks = ["ci/build", "ci/test", ...]`
    declares which checks must pass on a snapshot for `<name>@tested` to
    advance to it (up to 64 checks per branch).
  * `[checks.<name>] paths = ["src/", ...]` declares the default path
    prefix grant for a runner minted for `<name>`.
* **Narrow CI runner sessions (`POST /v1/sessions/ci`, `vl session ci`):**
  * Mints a short-lived (default 1 hour, max 24 hours) runner session with
    `agent_runner = true`.
  * When `check` is named and `only` is omitted, the server reads `.veilrules`
    on the default branch and narrows `only` to `[checks.<check>].paths`.
  * The minting caller must be able to read every path in `only` (and an
    un-narrowed runner session requires project admin or full-view access).
  * A runner session (`Caller::is_runner()`) is refused on `POST /objects`,
    `POST /push`, `POST /land`, and `POST /changes` with `403 agent_session`:
    it can only read what its narrowed grant allows and report check results.
* **Reporting and reading check results (`POST /v1/projects/{p}/checks`, `GET /v1/projects/{p}/checks`, `vl checks`):**
  * `POST /v1/projects/{p}/checks` accepts `{snapshot, name, state, summary, url, log}`.
    The caller's `snapshot` id (real or projected) is resolved to the
    canonical `commits.snapshot` on `main` (or any project branch), verified
    against the caller's view, and stored with the runner's readable path
    footprint (`session_paths`, `admin_only`).
  * `GET /v1/projects/{p}/checks?rev=<rev>` resolves `rev` (default `main`)
    through the reader's view, filters stored checks so a reader only sees a
    check if the reader's `View` can see every path the runner could read
    (admin-only checks are visible only to admins; path-narrowed checks require
    `view.sees_under(prefix)` for every prefix in `session_paths`), and
    projects `CheckResult.snapshot` into the reader's view.
* **Land first, test after, and `<branch>@tested` (`GET /v1/projects/{p}/tested/{branch}`, `vl tested`):**
  * Landings (`POST /land`, `POST /changes`, `POST /push`) never wait for CI
    runners; failing or absent checks never block a landing.
  * Whenever a check passes on snapshot `S`, `advance_tested` checks each
    branch whose tip reaches `S` along first-parent ancestry (up to 1,024
    commits). If `[branches.<branch>].required_checks` is non-empty and every
    required check has `state = 'pass'` on `S` (under the `.veilrules` at the
    branch tip), `tested` is updated in a serializable transaction:
    * Only advances forward: if the existing `tested.snapshot` is on the same
      first-parent lineage and has `depth <= new_depth` (closer to the tip), a
      late pass on an older ancestor never moves `<branch>@tested` backwards.
  * `<branch>@tested` is served in `GET /v1/projects/{p}/tips` (`Tips.tested`,
    projected per reader), resolved by the server query API
    (`/q/resolve?rev=main@tested`) and local revset parser (`main@tested`,
    stored as `origin/main@tested` in `remote_tags` on `vl pull`), and shown
    by `vl tested`.
* **Agents and workspaces start from `main@tested` by default:**
  * `POST /v1/sessions/agent` returns `tested: Option<ObjectId>` (the caller's
    projected `main@tested`).
  * `POST /v1/projects/{p}/changes` with `base` omitted (or all-zero) defaults
    to `<onto.branch>@tested` (falling back to the branch tip when no tested
    tip is recorded yet).
  * `vl ws new <name>` (when `-r` is omitted) and `vl change new` (when
    `--base` is omitted) start from `main@tested` if present in `remote_tags`,
    while a person can still pass `-r main` or `--base <rev>`.

#### Bounds

* **Per check result:** `name` ≤ 64 bytes (`MAX_CHECK_NAME`, ASCII graphic, no
  `..`, no control characters); `summary` ≤ 512 bytes (`MAX_SUMMARY_BYTES`, no
  control characters); `url` ≤ 1,024 bytes (`MAX_URL_BYTES`, `http://` or
  `https://` only); `log` ≤ 64 KiB (`MAX_LOG_BYTES`, no NUL bytes).
* **Per snapshot (`MAX_CHECKS_PER_SNAPSHOT = 64`, `MAX_TIP_LOG_BYTES = 256 KiB`):**
  at most 64 distinct check names per snapshot and at most 32 checks per
  runner on a single snapshot (`MAX_RUNNER_CHECKS_PER_SNAPSHOT = 32`); when a
  snapshot's total logs exceed 256 KiB, the oldest check logs on that snapshot
  are trimmed (`log = NULL`).
* **Per runner (`MAX_RUNNER_CHECKS = 256`, `MAX_RUNNER_LOG_BYTES = 1 MiB`):**
  across all snapshots, a runner retains at most 256 check results (oldest
  evicted) and at most 1 MiB of logs (oldest logs trimmed to `NULL`).

#### Guarantees and their tests (`server_hub::ci`)

| # | Guarantee | Test |
|---|---|---|
| 1 | A CI runner sees only what its grant allows. A result names nothing its readers can't see. A runner can't move any branch or land anything. | `runner_sees_only_its_grant_and_results_respect_visibility_and_runner_cannot_write_code`, `agents::every_route_that_takes_a_path_or_a_revision_is_classified_and_narrowed` |
| 2 | `main@tested` only ever moves to a tip whose required checks all passed, never backwards, and correctly across two servers and restarts. | `main_at_tested_moves_only_forward_when_required_checks_pass_across_servers_and_restarts` |
| 3 | A failing or absent runner never blocks landings; `main@tested` just stays put. | `failing_or_absent_runner_never_blocks_landings_and_tested_stays_put` |
| 4 | Agents start from `main@tested` by default, and a person can still choose another base. | `agents_and_workspaces_start_from_main_at_tested_by_default_and_person_can_choose_base` |
| 5 | Results and their logs are bounded per tip and per runner. | `check_results_and_logs_are_bounded_per_tip_and_per_runner` |

#### Threat review (design §6 Threat 10, plus visibility and DoS)

| # | Attacker | Tries | Result | Test |
|---|---|---|---|---|
| 1 | A compromised CI runner (`POST /v1/sessions/ci`) | reads paths outside its `[checks.<name>].paths` or `only` grant | refused with `403` on every path-taking route and projected out of every snapshot/tree | guarantee 1 |
| 2 | A compromised CI runner | pushes objects, moves a branch, lands a change, or creates a server-side change | refused with `403 agent_session` (`Caller::not_runner`) before touching objects or branches | guarantee 1 |
| 3 | A non-admin user (`dev` without `billing/`) | mints a CI runner session for `ci/billing` (`paths = ["billing/"]`) | refused with `403`: caller cannot delegate paths their own view cannot see | guarantee 1 |
| 4 | A check runner for a restricted area (`billing/` or admin-only) | writes restricted file contents or paths into `summary`, `url`, or `log` | `GET /checks` filters results by the reader's `View` against the runner's readable footprint (`session_paths`, `admin_only`) and projects `snapshot` into the reader's view | guarantee 1 |
| 5 | An out-of-order or replayed runner | reports `pass` on an older ancestor after `main@tested` already moved to a newer snapshot, or reports `pass` on only a subset of `required_checks` | `tested` tracks `(lineage, depth)` in Postgres under `SERIALIZABLE` and never moves to a deeper (older) ancestor or an incomplete check set | guarantee 2 |
| 6 | A dead, slow, or failing CI runner | stalls or reports `fail` on `main` | landings proceed immediately without waiting on CI; `main@tested` remains at the last passing snapshot and agents branch from `main@tested` | guarantee 3, guarantee 4 |
| 7 | A noisy or hostile runner | floods `POST /checks` with huge logs, control sequences, `javascript:` URLs, or thousands of check names | validated (`MAX_CHECK_NAME`, `MAX_SUMMARY_BYTES`, `MAX_URL_BYTES`, `MAX_LOG_BYTES`) and bounded per snapshot (`64` checks, `256 KiB` logs) and per runner (`256` checks, `1 MiB` logs) | guarantee 5 |

#### Reverting

Revert the merge commit. The new tables (`checks`, `tested`) and column
(`sessions.agent_runner`) in migration `0025` are ignored by older server
binaries; `Tips.tested`, `AgentSession.runner`, and `AgentSession.tested` use
`#[serde(default)]`; and `<branch>@tested` tags in `remote_tags` are ordinary
remote tag entries.

### 13.31 S22: embargoes through the server, and the release service (built)

Milestone S22 of `docs/design/server/phase-4-agent-scale.md` (§4.8, decisions 8
and 9, §6 rows 8–12, §8). Code: `crates/veil-server/src/embargo.rs` (push
validation and recording, visibility checks, `release_due` and `release_one`,
`release_route`), migration `0023_embargoes.sql` (`branches.hidden_for_embargo`,
`embargo_lines`, `embargo_snapshots`), minimal wiring in `sync.rs`, `api.rs`,
`landing/`, `changes.rs`, `query/mod.rs`, `search/` and `derive/mod.rs`,
`veil-core/src/embargo.rs` (`embargo_branch`, `embargo_id_of_branch`,
`active_embargoes`, `follow`), `veil-core/src/hub/wire.rs` (`PushRequest.embargoes`,
`Tips.embargoes`), and `crates/vl/src/hub.rs` (`vl merge --embargo-for`,
`vl push`, `vl pull`, `vl embargo follow`, `vl embargo release`). Nothing new
is encrypted: embargoes are server-enforced permissions that turn public at a
deadline.

```text
vl merge SOURCE --embargo UNTIL [--embargo-for GROUP...] [-m MSG]
vl embargo follow [ID]
vl embargo release ID
```

#### The design as built

* **Hidden embargo lines (`embargo/<id>`).** When an embargoed merge into a
  branch (`main`) is pushed and its scope's groups exist on the server, `vl push`
  sends the `EmbargoRecord` in `PushRequest.embargoes` and directs the branch
  update to `embargo/<id>`. The server (`embargo::prepare_push`) checks that the
  caller is a member of one of the embargo's groups (or an admin) and that every
  named group exists on the project, diverts any push of `main` carrying an
  unreleased embargo onto `embargo/<id>`, stores the branch with
  `branches.hidden_for_embargo = <id>`, records `(project_id, embargo_id,
  group_names, target_branch, embargo_branch, until_ms, released_at,
  record_json, created_by, created_at)` in `embargo_lines`, and tags every
  snapshot on the line (real, origin, and projected) in `embargo_snapshots`.
  The target branch (`main`) does not move until release.
* **Visibility before release.** While `embargo_lines.released_at` is `NULL`:
  * Only members of `embargo_lines.group_names` and project admins see
    `embargo/<id>` in `GET /v1/projects/{p}/tips` (along with its `EmbargoRecord`
    in `Tips.embargoes`) and in `POST /v1/projects/{p}/history`.
  * `embargo_snapshots` rows for an unreleased embargo are invisible to
    everyone outside the embargo by every route: `sync::resolve_for`,
    `sync::history`, `sync::fetch`, `POST /v1/projects/{p}/land`,
    `POST /v1/projects/{p}/changes`, `GET /v1/projects/{p}/q/…`, and
    `GET /v1/projects/{p}/q/search` and `grep`. Every refusal uses the exact
    same status code and message as a non-existent revision or branch (`404`, or
    `400 snapshot … was not uploaded`).
  * S12's deriver (`derive::catch_up`) and S15's search indexer (`search::index`)
    skip `branches WHERE hidden_for_embargo IS NOT NULL`, so embargoed snapshots
    never enter the derived commit graph, viewer graphs or search shards before
    release, and neither `policy_version` nor any public branch tip changes when
    an embargo is pushed.
* **`vl embargo follow [ID]`.** Pulls from `origin` (receiving `Tips.embargoes`
  and `origin/embargo/<id>` tags for the embargoes the caller is in), saves each
  `EmbargoRecord` into the local keychain, rebases `embargo/<id>` onto the
  newest tip of `main` when `main` moved ahead, pushes the rebased embargo line,
  and checks out the hidden line (when one unreleased embargo is active or `ID`
  is given) or lists the caller's active embargoes. Someone outside the embargo
  receives neither the branch nor the record, and `vl embargo follow <id>` fails
  with the same message as for an unknown id.
* **Scheduled release and landing at release.** Every server runs a background
  release task (`embargo::run_loop`) that calls `embargo::release_due`:
  * **Database clock and idempotent landing:** deadlines are compared solely
    against PostgreSQL's `clock_timestamp()` (`until_ms <= (extract(epoch FROM
    clock_timestamp()) * 1000)::BIGINT`), never a client's or an application
    server's local clock.
  * **Landing onto the target branch:** for each due embargo whose hidden
    branch still exists, `release_one` queues a deterministic landing ticket
    (`embargo-<project_id>-<embargo_id>`) onto `target_branch` (`main`) with
    `ON CONFLICT (ticket) DO NOTHING` and waits for S17's fenced landing service
    to land the embargoed stack onto `target_branch` once, recording each
    server-signed snapshot's author in `snapshots.author` (BUG-1581).
  * **Clearing the embargo:** in one transaction after the landing succeeds,
    `release_one` sets `embargo_lines.released_at` and updates
    `record_json.released_at`, deletes `branches WHERE name = 'embargo/<id>'`,
    deletes the embargo's `embargo_snapshots` rows, notifies `pg_notify` on
    `TIPS_CHANNEL`, and wakes `derive::landed` so derived history and search
    catch up on `main`.
  * **Retries and conflicts:** if a release attempt fails before finalizing or
    hits a content conflict on `target_branch`, `released_at` remains `NULL`, so
    a transient failure is retried on the next tick and a conflicted line is
    kept on `embargo/<id>` for a member to rebase and push again.
  * **Early release (`vl embargo release <id>` and `POST …/embargoes/{id}/release`):**
    when a member of the embargo (or an admin) pushes an `EmbargoRecord` with
    `released_at` set or calls `release_route` (which drops bulkhead gates via
    `limits::leave_gates` before waiting, BUG-1635), `embargo::release_one`
    lands the embargo on `target_branch` and releases it immediately.

#### Guarantees and threat review (phase 4 §6 rows 8–12, and S22's 5 guarantees)

| # | Guarantee / Threat | Mitigation | Test (`server_hub::embargo`) |
|---|---|---|---|
| 1 | Embargoed content is invisible to everyone outside the embargo until release, by every route | `embargo/<id>` filtered from `tips` and `history`; `embargo_snapshots` refused identically to unknown ids in `fetch`, `land`, `changes`, `q/…`, `q/search`, `q/grep`; skipped by `derive` and `search::index` | `guarantee_1_embargoed_content_is_invisible_outside_the_embargo_by_every_route` |
| 2 | Release happens at the deadline and never before (clock skew, restarts, several servers, failed release job retried) | Deadlines judged by PostgreSQL `clock_timestamp()`; deterministic ticket `embargo-<project>-<id>`; failed release leaves `released_at IS NULL` and retries on the next tick | `guarantee_2_release_happens_at_the_deadline_and_never_before` |
| 3 | Landing at release puts exactly the embargoed changes on `main`, once | `release_one` queues and lands the hidden line's stack onto `main` through S17's fenced landing service before `released_at` commits, recording `snapshots.author` | `guarantee_3_landing_at_release_puts_exactly_the_embargoed_changes_on_main_once` |
| 4 | `vl embargo follow` shows a member only what they're in | `Tips.embargoes` and `embargo/<id>` branches are filtered by the caller's group memberships (or admin); `vl embargo follow` pulls, rebases, and checks out only visible embargoes | `guarantee_4_vl_embargo_follow_shows_a_member_only_what_they_are_in` |
| 5 | Nobody outside the embargo learns that it exists, beyond what decision 8 allows | `main` and `policy_version` do not move when an embargo is pushed; probing `embargo/<id>` or its snapshots returns the exact same `404`/`400` as a random non-existent name | `guarantee_5_nobody_outside_the_embargo_learns_that_it_exists` |
| 6 | S14: `q/blame` and `q/history` (with `follow` across renames) never show embargoed content, paths or versions outside the embargo | `query::resolve_rev` and `query::history` cursors check `embargo::is_withheld_for`; hidden `embargo/<id>` branches are excluded from `derive`, so embargoed paths on `main` answer byte-for-byte as missing paths (`404`) | `s14_blame_and_file_history_never_show_embargoed_content_paths_or_versions` |
| 7 | S11: an agent session sees and lands embargoed work only if its person is in the embargo; narrowed sessions stay within their paths; release landing checks `landing::agent_stack` | `/v1/projects/{p}/embargoes/{id}/release` classified in `agents::every_route_that_takes_a_path_or_a_revision_is_classified_and_narrowed`; `embargo::release_one` enforces `landing::agent_stack` when an agent session asks for release | `s11_agent_sessions_and_narrowing_on_embargoes_and_release_landing` |
| 8 | S6: the Veil daemon never serves an embargoed object to a client outside the embargo | Outsiders receive grants only for projections without the embargo; their root trees never reach embargoed trees or blobs in the daemon's warm store | `s6_daemon_never_serves_an_embargoed_object_outside_the_embargo` |
| 9 | S17: the release landing records `snapshots.author`, gives back its bulkhead places before waiting (`limits::leave_gates`), and lands once across two servers | `release_one` drops bulkhead gates before `landing::wait`, `Services::waiters` fans out deterministic ticket outcomes to all concurrent waiters, and `landing::service` records each change's author in `snapshots.author` | `s17_release_landing_records_author_leaves_bulkhead_gates_and_lands_once_across_two_servers` |

### 13.36 S20: automatic bisect and revert (built)

Milestone S20 of `docs/design/server/phase-4-agent-scale.md` (§4.8, §4.9,
decision 11, §6 rows 9 and 14, §8). Code: `crates/veil-server/src/bisect.rs`,
migration `0026_bisect_and_revert.sql` (`landing_queue.priority`,
`bisect_leases`, `bisects`, `bisect_reverts`), and minimal hooks in `ci.rs`,
`landing/rules.rs`, `landing/service.rs`, `landing/merge.rs`, `events.rs`,
`api.rs`, and `lib.rs`.

#### The design as built

* **Trigger (`bisect::on_check_recorded`).** Whenever `POST /v1/projects/{p}/checks`
  records a `pass` or `fail` result on a real snapshot `S`, `on_check_recorded`
  inspects every protected branch of the project where:
  * `branches.hidden_for_embargo IS NULL` and `!branch.starts_with("embargo/")`
    (embargo lines are never bisected or auto-reverted into public branches);
  * the branch's `.veilrules` has `protected = true`, `auto_revert` not `false`
    (default `true` on protected branches, product decision 11), and lists the
    check in `required_checks`.
* **Candidate narrowing (`collect_candidates`).** When a required check fails on
  a snapshot strictly ahead of `<branch>@tested` along the branch's first-parent
  chain (bounded at `MAX_BISECT_LANDINGS = 1,024`), the server acquires the
  branch's `bisect_leases` lock and walks `(tested..=bad]` in chronological
  first-parent order. A landing is included in `candidates` only if:
  1. it is not withheld by an unreleased embargo (`embargo::is_withheld_for_query`);
  2. its first-parent edit set (`edits::edit_set`) touches at least one path
     matching `[checks.<name>].paths` (if configured in `.veilrules`); and
  3. its edit set touches at least one path inside the reporting runner's
     readable footprint (`session_paths`), so bisect never asks a narrowed
     runner to test a snapshot whose edits collapsed out of the runner's view.
* **Bounded $k$-way midpoint search (`drive_bisect`, `probe_indices`).**
  * Using S19's `checks` table, any candidate with an existing `pass` advances
    the lower bound (`lo = i + 1`) and any candidate with an existing `fail`
    tightens the upper bound (`hi = i`).
  * While `lo < hi`, the server picks up to `k` evenly-spaced interior indices
    in `(lo..hi)` where `k = [checks.<name>].parallel` (`1..=8`, default `1`),
    persists `probes` in `bisects`, and emits `check.requested` SSE events
    (`reason: "bisect"`) to runners and viewers permitted to see both the check
    and the projected probe snapshot.
  * Bisect finishes searching in at most $\lceil \log_{k+1}(N) \rceil$ rounds.
* **Flake-immune confirmation (`confirming` phase, Threat 14).**
  * Once `lo == hi`, candidate `C = candidates[lo]` and its first parent `P`
    enter `phase = "confirming"`.
  * Before reverting `C`, the server requires two independent failing runs on
    `C` (`checks.run_count >= 2` with `state = 'fail'`) and a passing run on
    `P` (`state = 'pass'`). Missing confirmations emit `check.requested` SSE
    events with `reason: "confirm"` (for `C`) and `reason: "confirm-parent"`
    (for `P`).
  * If `C` passes on its confirmation re-run or `P` fails, bisect transitions to
    `phase = "flaky"` and never reverts anything.
* **Priority-lane server revert via S17 and S18 (`revert_confirmed_culprit`).**
  * When `C` is confirmed (`culprit_fails >= 2` and `parent_passes >= 1`), the
    server constructs a revert snapshot signed by `hub.identity` with
    `parents = [C]`, `tree = P.tree`, `author = "server"`,
    `description = "revert <C.change_id>"`, and
    `agent = Attribution { agent: "server/bisect", task: Some("revert:<C.change_id>"), .. }`.
  * The server records `(project_id, branch, lineage, culprit)` in
    `bisect_reverts` (`ON CONFLICT DO NOTHING`) and enqueues
    `Entry::plain(revert_snap_id, C)` in `landing_queue` under a deterministic
    ticket (`revert-<project>-<branch>-<lineage>-<culprit_prefix>`) with
    `priority = 1`.
  * `Service::ready` orders queued entries by `priority DESC, created_at, seq`,
    so the revert lands ahead of ordinary queued changes (`priority = 0`).
  * S17 computes the edit set of `revert_snap` against `C` (`P.tree` vs
    `C.tree`, the exact inverse of `C`'s edits) and either fast-paths it onto
    the current branch tip or spawns an S18 3-way content merge (`base = C.tree`,
    `ours = tip.tree`, `theirs = P.tree`), surgically reversing only `C`'s edits
    while preserving later changes' edits. If a later change modified the same
    lines as `C`, S18 reports a conflict and bisect records `phase = "conflict"`.
* **Visibility (`docs/VISIBILITY.md`) and routes (`GET /v1/projects/{p}/bisect/{branch}`).**
  * `events::emit_check_requested`, `events::emit_reverted`, and
    `bisect::status_route` project every snapshot (`good`, `bad`, `candidates`,
    `probes`, `culprit`, `revert`) into each viewer's `View`, omitting snapshots
    that collapsed into their parent's projection or are withheld by an embargo,
    and hiding `check` whenever `!ci::can_see_check(...)`. If neither the check
    nor the culprit/revert is visible to a viewer, `GET …/bisect/{branch}`
    returns `404`.

#### Guarantees and threat review

| # | Guarantee / Threat | Mitigation | Test (`server_hub::bisect`) |
|---|---|---|---|
| 1 | Bisect finds the first failing landing in bounded steps ($\le \lceil \log_{k+1}(N) \rceil$) and never asks a runner for a check result outside its footprint | `collect_candidates` filters `(tested..=bad]` by `[checks.<name>].paths` and runner `session_paths`; `probe_indices` probes $k$ midpoints per round | `bisect_finds_first_failing_landing_in_bounded_steps_and_respects_runner_footprint` |
| 2 | A confirmed culprit is reverted via S17's priority lane (`priority = 1`), server-attributed, surgical (preserving subsequent commits' files and lines via S18), and only on protected branches allowing `auto_revert` | `revert_confirmed_culprit` signs as `"server"` / `"server/bisect"`, queues `Entry::plain(rev, culprit)` at `priority = 1`, and checks `Rules::allows_auto_revert` | `confirmed_culprit_is_reverted_through_s17_priority_lane_server_attributed_and_surgical` |
| 3 | Flaky check immunity (design §6 Threat 14): a single failure or infrastructure flake never reverts anything | `confirming` phase requires `run_count >= 2` failures on `culprit` and a `pass` on `culprit_parent`; a passing re-run or failing parent marks `phase = "flaky"` | `only_confirmed_culprit_is_reverted_and_flaky_check_never_reverts` |
| 4 | Per-viewer visibility (`docs/VISIBILITY.md`) and embargo safety (design §6 Threat 9): nothing hidden leaks in revert commits, messages, SSE events, or status; embargoed changes never bisect or revert into public branches | `embargo/*` and withheld snapshots are excluded from bisect; `status_route`, `emit_check_requested`, and `emit_reverted` filter by `can_see_check` and `visible_projection` | `nothing_hidden_leaks_in_revert_messages_events_or_status_and_embargo_never_reverts_early` |
| 5 | Bounded and safe across multiple servers and restarts: one bisect per branch at a time, and a revert lands at most once | `bisect_leases` fences concurrent servers per `(project_id, branch)`; `bisect_reverts` and deterministic `revert-…` tickets guarantee at-most-once revert landing | `bisect_and_revert_are_bounded_and_safe_across_two_servers_and_restarts` |

### 13.37 S29: merging packs and pack garbage collection (`crates/veil-server/src/pack_gc.rs`, `migrations/0027_pack_gc.sql`, built)

Design: [`docs/design/server/storage-and-cost.md` §8](design/server/storage-and-cost.md).

* **Why.** S28 packs every push into one storage object (`veilpack3\n`), read by range. Over thousands of small pushes a project accumulates thousands of small packs (`pack::Packs` searches their indexes newest first), and unreferenced objects—from force-pushes, deleted branches, superseded S15 search segments, and abandoned staged uploads—stay in storage until reclaimed. S29 adds a bounded background compaction and garbage-collection job per project (`pack_gc::run_project`, `pack_gc::maybe_schedule`).
* **Schema (`migrations/0027_pack_gc.sql`, migration 27).**
  * `packs.discarded_at BIGINT`: millisecond timestamp set when a pack transitions to `DISCARDED` (`state = 2`), either because an upload was refused/abandoned or because a merge/GC pass replaced a listed pack.
  * `unreferenced_objects (project_id BIGINT, object_id TEXT, since_ms BIGINT, PRIMARY KEY (project_id, object_id))`: records when an object in `project_id` was first observed to be unreferenced by any live root, enforcing the retention window (`DEFAULT_RETENTION_WINDOW_MS`, 1 hour by default) before deletion so S3 thin clones (which keep no server anchors) and racing pushes never see an object vanish under them.
* **Crash-safe write-then-switch-then-delete.** A pack is never edited in place:
  1. **Per-project advisory lock and shedding:** one server at a time runs `pack_gc` on a project (`pg_try_advisory_lock(LOCK_BASE ^ project_id)` on `derive.db`), acquiring a background worker permit (`derive::Workers::permit`) and yielding to landings and pushes via `limits.derive_turn()` (`limits::DERIVE_PAUSE`).
  2. **Bounded index and object reads:** source pack indexes are read one at a time under `pack::INDEXES_HELD` (`Objects::index_bound`), deduplicating objects across the batch and filtering out any expired-unreferenced objects. Live entries are copied in contiguous range spans (`COPY_SPAN = 2 MiB`) under `store::ReadAhead` (`store::DECODED_IN_FLIGHT`), verifying every entry header (`pack::entry`), and written as new `STAGED` job packs (`person_id IS NULL`, capped at `MAX_MERGED_BYTES = 32 MiB` and `pack::MAX_OBJECTS = 262,144`) via `Objects::put_job_pack` (which inserts the `STAGED` row before writing the storage object).
  3. **Atomic switch transaction:** in one `READ COMMITTED` transaction (`db::transaction`), the job locks the replaced packs (`SELECT ... FOR UPDATE`), verifies they are still `LISTED` (and, when GC drops unreferenced objects, verifies the project's ref/push stamp `RefStamp` is unchanged), updates the new pack(s) to `LISTED` (`state = 1`), and marks the replaced packs `DISCARDED` (`state = 2`, `discarded_at = now_ms`).
  4. **Cross-server lookup coherence:** the server that ran the switch calls `Objects::listed_here` and `Objects::forget_packs` (`Packs::forget`). Other servers prune unlisted packs on `Packs::refresh_in`, and if a ranged read (`Objects::try_pack_range`, `Objects::stored`, `Objects::get_blocking`, `Packs::find_paged_in`) encounters a pack that was already merged and swept after its grace window, it forgets that pack and refreshes the project's listing seamlessly without surfacing an error.
  5. **Grace-period sweep:** once `now_ms - discarded_at >= pack_grace_ms`, `sweep_discarded` deletes the storage object (`store.delete`) and then deletes the `DISCARDED` row from `packs`. Uncommitted job packs from an interrupted run (`state = 0 AND person_id IS NULL`) and abandoned client uploads older than `staged_grace_ms` are discarded and swept by `sweep_staged`.
* **Garbage collection reachability closure.** `mark_and_sweep_loose` walks the object graph starting from all server roots of the project:
  * all `branches` (both public branches and hidden embargo branches `embargo/<id>` where `hidden_for_embargo IS NOT NULL`),
  * `embargo_lines` (`record_json`) and `embargo_snapshots` (S22),
  * `change_refs` (S10 API commits),
  * `landing_queue` (`stack` and `result` JSON) and `landings` (S17, S18),
  * `checks` and `tested` (S19 CI results),
  * `tags` and `pr_revisions` / `prs` (when present) and `Atag` tag objects,
  * `Snapshot` trees, parents, predecessors, and S11 `attempts`,
  * `origins` and `projections` memos for reachable snapshots (and standalone projection memos),
  * S12 `graph.changed` derived objects and S15 `search_shards.segments` for live branches and the project-wide `names` index,
  * and every object in an active `STAGED` upload pack (`state = 0`).

| # | Guarantee | Test (`server_hub::pack_gc`) |
|---|---|---|
| 1 | Merging never loses or changes an object (`get`, `get_many`, `get_range`, `get_staged`), with concurrent readers across two servers and crashes mid-merge (pre-switch and post-switch) | `guarantee_1_merging_never_loses_or_changes_an_object_across_servers_and_crashes` |
| 2 | GC deletes only what nothing references (branch, tag, PR, embargo line, landing queue, S11 attempt, S19 CI result, projection memo, S15 search segment, S28 staged upload), respects the retention window, and never deletes an object a racing push is about to reference | `guarantee_2_gc_deletes_only_unreferenced_objects_respects_retention_window_and_racing_push` |
| 3 | GC never deletes a hidden embargo line's objects before release | `guarantee_3_embargoed_objects_never_deleted_before_release` |
| 4 | Merge and GC work per run, memory (`INDEXES_HELD`, `DECODED_IN_FLIGHT`) and storage requests are bounded, and yield to landings and pushes (`limits::DERIVE_PAUSE`) | `guarantee_4_merge_and_gc_are_bounded_and_yield_to_landings_and_pushes` |
| 5 | Storage objects, bytes, and merge storage requests before and after merging 10,000 small pushes | `guarantee_5_cost_of_merging_10000_small_pushes` |

