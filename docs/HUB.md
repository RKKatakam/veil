# Veil Hub: the server design

> **Sources of truth:** `docs/OVERVIEW.md` (what Veil is) and `docs/VISIBILITY.md` (who can see what). This document is how the server implements them. Where it disagrees with either, they win.

Status: **milestone S1 is built** (`crates/veil-server`, the `vl` client
commands, 2026-11-06): the server core, sign-in, the permission model,
sync with fetch on demand, enforcement and secrets sealed on the device.
**§13 records what was built and every decision S1 made**; where §1–§12
propose something §13 decided otherwise, §13 is what runs. Later
milestones are in §13.9. Statements about what Veil does today cite the
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
  Embargoed changes are encrypted the same way until release.
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
* **Encrypting code.** Only secrets and embargoed changes are encrypted.
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
                         └── deadline worker (embargo release, §8.2)
```

| Component | Does | Built from |
|---|---|---|
| **API server** | Sign-in, the sync protocol (§4), the JSON API, permission checks on every request, push validation | Rust, running `veil-core` |
| **Repo workers** | Land changes (merge or rebase onto the latest branch, then move it), compute indexes, run history and search queries | `veil-core` (`merge.rs`, `transaction.rs`, `graph_index.rs`, `blame.rs`, `search.rs`) over object storage |
| **Metadata DB** | People, devices, groups, managers, admins, folder access, branch tips, PRs, review threads, approvals, CI jobs, the audit log | **YugabyteDB** (owner, 2026-11-05: open source, Spanner-style scaling). The schema is PostgreSQL-compatible, so plain **PostgreSQL** runs it for development and CI. A branch move is one conditional `UPDATE` |
| **Object storage** | File contents, trees and snapshots, each by its BLAKE3 id | S3-compatible; immutable objects, served through caches |
| **Web client** | Browsing, review, administration | TypeScript UI; `veil-core` in WASM only where a secret is opened (§10) |
| **Deadline worker** | Notifies or releases embargoes on time | §8.2 |

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
| **Someone who breaks into the server** | Read all code and metadata; deny service; change permissions in the DB | Read secrets or unreleased embargoed changes; forge snapshot signatures | Ordinary server hardening, audit log, backups. Secrets and embargo keys never reach it (§6, §8) |
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
| Landings per agent | per project setting | one runaway agent can't starve the rest |

`error` frames carry `retry_after_ms`. Anonymous reads of `public` folders
have their own, lower limits.

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

* paths that today's client cloaks become private folders, with access for
  the people who could open them; their secrets stay encrypted;
* `.env` files start syncing, encrypted, only after an explicit upgrade
  step that lists them;
* nothing is made public or decrypted silently;
* `vl cloak`, `vl isolate` and `vl expose` become aliases of `vl access`,
  or are removed, in the simplification pass.

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
  title, body,                          // plain text; encrypted only for an embargoed PR
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

Embargoes are built in today's client (ARCHITECTURE.md §7, CRYPTO.md C7):

* the embargoed merge's content, description and history are encrypted
  under an embargo key, wrapped for its audience;
* a signed record commits to the key's fingerprint and the deadline;
* release publishes the key in the record, and every reader checks it;
* anything built on the fix stays hidden too; history withheld from others
  is computed by `remote::embargo_withheld`;
* release happens on the first `vl` run by a key holder after the deadline,
  or by `vl embargo release`.

### 8.2 A trusted clock for deadlines

The server runs a **deadline worker**. At the deadline it notifies the
embargo's key holders, whose `vl` releases and pushes; clients can also
check deadlines against signed time from the server instead of a local
clock that may be wrong (the engine's clock is replaceable for this,
`clock.rs`, ARCHITECTURE.md §13).

An optional **escrow** mode lets the release happen even if no key holder
is online: the embargo key is also HPKE-wrapped to a separate release
service, bound to the embargo id and deadline, and that service publishes
it at the deadline. It needs a new embargo record version and signing
context (FORMAT.md §4).

### 8.3 On the server

* The groups named (`--embargo-for`) get the fix at once: code, message
  and history, decrypted on their devices. Everyone else, the public
  included, sees nothing of it until release.
* **Embargoed changes stay encrypted on the server**, because they often go
  to people outside the project (`distro-partners`).
* Release is a push of the record with its key. The server checks the
  fingerprint, and from then on the content is ordinary: plain text,
  merged, indexed and searchable like any other.
* An embargoed PR exists only for its groups (§7.1).
* **Landing an embargoed change before release** needs the embargo key, so
  it runs on a key holder's device or a machine in its groups (§7.5).

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
   * the deadline worker and escrow (§8.2), CI on machines (§5.5), the web
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
| Migrations | `db::migrate`, `migrations/0001_initial.sql`, `0002_device_vouches.sql` (pending devices, vouches: §13.11), `0003_invites_and_key_sharing.sql` (invites, key requests, pending devices by fingerprint and the fingerprints a person waits for, devices barred from one project: §13.12) | each in its own transaction, recorded in `schema_migrations`; servers starting together race on its primary key and the loser re-checks. On PostgreSQL DDL is transactional; on YugabyteDB DDL inside a transaction block is applied statement by statement unless transactional DDL is enabled, so **migration files are idempotent** (`IF NOT EXISTS`) and a half-applied one is completed by the next start |
| Object storage | `store::BlobStore`: `FsStore` (a directory; unit tests, development) and `S3Store` (rusty-s3 request signing + reqwest; tested against MinIO) | key `p/<project id>/ab/cdef…`: projects never share an object; every read is re-hashed against its id; an in-memory cache of objects and decoded trees |
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
  takes effect on their next request.

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
| `GET /v1/projects/{p}/tips` | branches → tips as the caller sees them (projections) |
| `POST …/history {tips, stop}` | the caller's projected snapshots from `tips` down to `stop`, as object frames (`id ‖ len u32be ‖ object`) |
| `POST …/fetch {snapshot, objects: [{path, id, snapshot?}]}` | objects by id, each with the path where the client met it under that snapshot (its own `snapshot`, or the request's); the server walks the viewer's projection of that snapshot to that path and serves the object only if it is there. No list of what the client has; each request names an immutable object, so a per-viewer cache can serve it |
| `POST …/objects` | upload object frames: re-hashed, canonically decoded, format-checked, stored; invisible until a push reaches them. Answers a **receipt** per object (a server MAC over project ‖ person ‖ id) |
| `POST …/push {updates: [{branch, expected, new}], force, receipts}` | complete and check every new snapshot, then move the branches in **one serialisable transaction of compare-and-swaps** (`UPDATE branches SET target = new WHERE … AND target = expected`); one lost race rejects the whole push with 409 and `vl` retries |
| `GET …/access?path=` | the deciding line and who it names; only for a path the caller may read |
| `…/groups`, `GET|POST …/rings/{scope}`, `GET /v1/people/{name}/devices` | groups; key rings of secret scopes; a person's devices (active, the newest pending, removed), the vouches and invite joins the server stores, which devices check before sharing a key (§13.11, §13.12) |
| `POST /v1/devices/vouch {device, signature}` | the signed-in device vouches for another device of its person; a pending one becomes active |
| `GET /v1/people/{me}/pending/{fingerprint}` | one of the caller's own pending devices, by fingerprint; if none waits, the fingerprint is kept for the person for an hour, so the bound on pending devices never pushes that device out (§13.12) |
| `POST /v1/devices/remove {device, project?}` | remove a device: its person, from another device, everywhere (its sessions end); or an admin of `project` where the person takes part, from that project only (§13.12, BUG-843) |
| `POST …/invites {key, person, group, expires_at}`, `POST …/invites/join {key, device, signature}` | an admin records an invite's public key; the signed-in device joins under it, once, before it expires (§13.12) |
| `GET …/keys/pending` | the people whose devices may wait for keys, with their devices, vouches, joins and removed devices: a hint for the devices that share keys (§13.12) |

* **Fetch on demand (Scion):** `vl` asks for the tips, the snapshots it
  lacks, then trees from the root down and the files it needs, one request
  per tree level for every new snapshot at once, skipping what it already
  has. **Revision 1** (`Tips::revision`, performance round 2): a want may
  name its own snapshot, so a pull behind by many landings asks once per
  level instead of once per snapshot and level; `vl` asks a server of
  revision 0 the old way. A level of more than 2,000 objects is fetched as
  up to 8 requests at once (`Client::fetch_all`). From 16 objects a pull
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
  it; that is every object an entry names: its own, its `fallback`, and a
  conflict's terms, which `fetch` also serves at that path (BUG-834);
  anything else, stored or not, gets the answer a missing object gets, so a
  push never confirms a guess of a hidden file or folder: BUG-824),
  8 (§13.6), 10 (every
  new snapshot signed by a registered device key) and 12 (fast-forward
  unless an admin forces) are built. Cloaked lines and embargoed content
  are refused in S1. Not built: 9 (the server-side secret scan), 11, 13.
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
* **Embargoes and cloaked lines** cannot be pushed to the server yet.
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
2. **S3: fetch on demand in the client** — the partial-clone design
   (`docs/design/scale/6-partial-clone.md`): bounded cache, objects fetched
   when read, `vl ws mount` over the server; layered caches (per-machine
   daemon, regional caches) serving objects only after the server's check.
3. **The PR and review service** (§7), hidden PRs.
4. **Server-side merges and batched landings** (§9.1), with the gates of
   §9.2.
5. **Precomputed history and search APIs** (blame, file history, graph,
   search through the API).
6. **The embargo release service** (deadline worker, escrow, §8.2) and
   embargoes through the server.
7. **The web client** (§10).
8. **The simplification pass:** remove SFTP and path remotes (part 1,
   done), offline assumptions, cloak/scope jargon (OVERVIEW.md).

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
