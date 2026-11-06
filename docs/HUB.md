# Veil Hub: the server design

> **Sources of truth:** `docs/OVERVIEW.md` (what Veil is) and `docs/VISIBILITY.md` (who can see what). This document is how the server implements them. Where it disagrees with either, they win.

Status: **design. Nothing here is built yet.** The Hub is built **next**,
together with the permission model (OVERVIEW.md, "What exists today, and
what's next"). Statements about what Veil does today cite the document or
source file they come from; everything else is a proposal and is worded as
one.

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
* Path and SFTP remotes, which today's client supports, are removed in the
  simplification pass after the server lands (OVERVIEW.md).
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
   `finance` member's) checks the request against the server's records,
   wraps the keys for carol's registered devices and uploads the wraps.
   This is automatic; nobody runs a command.
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
   unnecessary: plain-file (SFTP and path) remotes, offline assumptions, old
   storage formats (still readable for `vl upgrade`) and old jargon (cloak,
   scope, isolate).
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
