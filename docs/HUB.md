# Veil Hub: design

Status: **design draft, post-1.0.** Nothing here is implemented. Veil 1.0
ships without a server: public code reaches GitHub through the Git bridge
([ARCHITECTURE.md §11](ARCHITECTURE.md#11-git-interop-git)), and closed code
goes to a path or SSH remote that needs nothing but SFTP
([ARCHITECTURE.md §1, §8](ARCHITECTURE.md#8-synchronisation)). This document
designs the hosted service that comes after: a GitHub-like product for
repositories that are partly open and partly closed, in which **the server
never holds a key that opens closed content**.

Every statement about how Veil behaves today cites the document or source
file it comes from. Everything else is a proposal, and is worded as one.

Contents:

1. [Goals, non-goals and personas](#1-goals-non-goals-and-personas)
2. [Architecture](#2-architecture)
3. [Security model and threat model](#3-security-model-and-threat-model)
4. [The smart sync protocol](#4-the-smart-sync-protocol)
5. [Pull requests and review on change ids](#5-pull-requests-and-review-on-change-ids)
6. [Access control](#6-access-control)
7. [CI on closed code](#7-ci-on-closed-code)
8. [Embargo service](#8-embargo-service)
9. [The web client](#9-the-web-client)
10. [MVP and phased roadmap](#10-mvp-and-phased-roadmap)
11. [Open questions and risks](#11-open-questions-and-risks)

---

## 1. Goals, non-goals and personas

### 1.1 Goals

* **Hosting.** Accounts, organisations, teams and repositories. A Hub
  repository is an ordinary Veil remote: `vl push`, `vl pull` and `vl clone`
  work against it, and a clone holds the full history the cloner may read.
* **Pull requests and code review keyed on Veil change ids**, so a PR
  survives rebases, amends and squashes (change ids are stable across
  rewrites, [ARCHITECTURE.md §5](ARCHITECTURE.md#5-the-snapshot-graph)).
* **One PR spanning open and closed files.** Each viewer sees the parts
  they hold keys for and an honest placeholder for the rest.
* **Per-scope access and approval rules.** A change to files in scope `ops`
  needs an approval from a member of `ops`, enforced by the Hub and
  verifiable by every client.
* **A web UI** for history, files, diffs, scopes and their membership logs,
  embargoes and the Hub's push log.
* **A trusted embargo-release clock**, so an embargo releases on time even
  when no key holder runs `vl` at the deadline (today release waits for "the
  first `vl` command a key holder runs after it",
  [guide/embargoes.md](guide/embargoes.md#deadlines-and-release)).
* **CI**, including on closed code.
* **Zero knowledge for closed content.** The server stores ciphertext and
  HPKE-wrapped scope keys only. Decryption and every content feature
  (diff, highlighting, search, conflict views, secret scanning of closed
  content) run in a client: `vl`, a desktop app, or the browser through a
  WASM build of `veil-core`.

### 1.2 Non-goals

* **Hiding metadata completely.** The Hub sees who pushes and pulls what and
  when, object sizes, tree shape and, until sealed tree names exist, the
  names of cloaked files (§3.3). The design reduces this and says exactly
  what remains; it does not promise metadata privacy.
* **Server-side features over closed content.** No server-side search,
  code navigation, blame, AI review or abuse scanning of closed content.
  Each of these is either client-side or limited to the public projection.
* **Protecting a user from their own compromised device.** A client that
  holds a key can leak what the key opens.
* **Retroactive revocation.** Revocation stays forward-only
  ([ARCHITECTURE.md, threat model](ARCHITECTURE.md#threat-model)). The Hub
  makes offboarding fast and lists what to rotate. It cannot un-share.
* **Replacing Git hosting for the public.** Public code can stay mirrored on
  GitHub (§5.8). The Hub is where mixed work is reviewed.
* **Reusing Git's wire protocol.** The protocol is Veil's own (§4), built on
  Veil packs and Veil's sync rules.

### 1.3 Personas

| Persona | Today (1.0) | What they want from the Hub |
|---|---|---|
| **Solo developer** (the owner, first user) | One repository: public code exported to GitHub with `vl git push`, closed code pushed to an SSH remote | One place to see all of it from any machine, a phone included; backups; CI for both halves; no server to run |
| **Small team with mixed open and closed code** (the owner's team) | A team SSH remote, scopes granted by hand with pasted `veil1…` keys, review on GitHub for the public part only | Review of *whole* changes, closed parts included; invitations without pasting keys; offboarding that lists what to rotate; per-scope approvals |
| **Open-source maintainer with outside contributors** | GitHub PRs for public code; the closed parts (deploy configs, release keys, internal docs) are invisible to contributors | Contributors open PRs against the public projection; maintainers review and merge them without exposing closed files; mixed PRs from insiders in the same queue |
| **Security team using embargoes** | `vl merge --embargo --until`, release by hand or by the next key holder's `vl` | Reports from outside researchers, private advisories, a release that happens on time, coordinated disclosure with downstreams, a fix that lands on GitHub the moment it is public |

---

## 2. Architecture

### 2.1 Components

```text
                    ┌──────────────────────────── trust: none for closed content ───────────────────────────┐
                    │                                                                                       │
 vl / desktop ──────┼──► API server ───────► metadata DB (accounts, orgs, refs, PRs, ciphertext comments)    │
 (keys, plaintext)  │     │  smart sync       ▲                                                             │
                    │     │  validation       │                                                           │
 browser ───────────┼──►  │  (veil-core,      │                                                           │
  web client        │     │   no identity)    │                                                           │
  (WASM veil-core,  │     ▼                   │                                                           │
   keys in a        │   repo workers ────► object storage (packs, partitioned by audience; immutable)       │
   worker)          │     │                                                                               │
                    │     ├──► public renderer (server-side pages of the public projection)              │
                    │     ├──► Git mirror worker (public projection → GitHub)                             │
                    │     └──► CI coordinator ──► hub-hosted runners (public projection only)              │
                    └───────────────────────────────────────────────────────────────────────────────────────┘
 static assets:     web client build ── signed manifest + transparency log (§9.5)
 separate domain:   release service (embargo escrow / drand time-lock, §8)
 customer-owned:    self-hosted CI runners (scope members, own identities, §7)
```

| Component | Does | Built from |
|---|---|---|
| **API server** | Accounts and sessions, the smart sync protocol (§4), REST/JSON API for the web client, push validation | Rust; runs `veil-core` with **no identity**, exactly as `remote::push` opens a remote today: `Repo::open(remote_backend, None, "remote")` (`crates/veil-core/src/remote.rs`, `push_with`) |
| **Repo workers** | One serialised writer per repository: applies accepted pushes, repacks, computes projections, embargo-release bookkeeping | `veil-core` (`Transaction`, `PackBuilder`, `gc`) over a `StorageBackend` on object storage |
| **Object storage** | Packs and indexes (`VEILPAK1`/`VEILIDX1`, ARCHITECTURE.md §10), key rings and embargo records as files, as in any `.veil/` | S3-compatible; packs immutable |
| **Metadata DB** | Accounts, identities, orgs, teams, repository ACLs, a mirror of each repository's view (tags, heads) for compare-and-swap, PRs, review threads (ciphertext bodies), signed approvals, invitations, CI jobs, audit log | PostgreSQL |
| **Web client** | All browsing and review of closed content; also signs approvals, ring changes and comments | TypeScript UI + `veil-core` compiled to WASM in a Web Worker (§9) |
| **Public renderer** | Pages for anonymous readers and search engines: the public projection only | Server-side, plaintext public content only |
| **Git mirror worker** | Exports the public projection to GitHub/GitLab | `veil-core` `git` feature; export is key-independent (§5.8) |
| **CI coordinator** | Queues jobs, dispatches to runners, stores signed statuses and sealed logs | §7 |
| **Release service** | Releases embargoes on time without the Hub holding their keys before the deadline | Separate deployment and operator; §8 |

### 2.2 The key property this design rests on

**The public projection, and every per-viewer projection, is computable
without keys.** Veil already decides what a public remote or Git receives
"by how each object is *sealed*, never by which keys this replica holds"
([ARCHITECTURE.md §11](ARCHITECTURE.md#export-what-git-may-see)). The
transfer filter reads only the envelope label of each object
(`Transfer::allowed` in `remote.rs` calls `Object::sealed_scope(raw)`), and
the withheld history of an unreleased embargo is computed from snapshot
fields and embargo records, whose release state is public
(`remote::embargo_withheld`, `Keychain::embargo_released`). Trees name each
entry's tier and label in plaintext ([FORMAT.md §3.2](FORMAT.md#32-binary-trees-encoding-2)).

So the Hub, holding no keys, can still:

* serve anonymous readers exactly what a `--public` remote would hold;
* serve each signed-in viewer only the ciphertext of scopes they are a
  member of (by the rings, which are plaintext signed logs), instead of all
  of it as a team SSH remote does today;
* compute which scopes a PR touches, by diffing trees by object id;
* carry review approvals across a rebase when the sealed objects of a scope
  did not change (deterministic sealing gives unchanged content the same
  id, [CRYPTO.md C1](CRYPTO.md#c1-sealed-objects-aes-siv-f3));
* mirror the public projection to GitHub.

This property must be kept as an engine invariant (§10.1).

### 2.3 What each component can and cannot see

| Component | Can see | Cannot see |
|---|---|---|
| API server, repo workers, DB, object storage | Everything in §3.3: public content in plaintext; ciphertext, labels, sizes and tree shape of closed content; rings (member ids, names, roles, generations, wrapped keys as ciphertext); embargo records; snapshot metadata; who did what when | Closed file contents, sealed descriptions, sealed review comments and CI logs, scope keys, embargo keys before release, identity secrets |
| Public renderer, Git mirror worker | The public projection, as a `--public` remote holds it | Anything sealed; rings (public remotes receive none, BUG-077, `remote.rs` module table) |
| Hub-hosted CI runners | The public projection | Anything sealed |
| Release service | Embargo records; in escrow mode, embargo keys escrowed to it (§8.3) | Scope keys, closed content outside embargoes |
| Self-hosted runners | What their scopes open, the CI secrets granted to them | Other scopes |
| Web client and `vl` | What the user's identity opens | Other scopes |

### 2.4 Data flows

**Push from `vl`** (§4 has the messages):

```text
vl (alice)                                   API server                      repo worker / storage
  │ snapshot, seal cloaked files locally        │                                  │
  │── hello, auth (identity signature) ────────►│                                  │
  │◄─ view: tags, heads, ring heads ────────────│                                  │
  │ compute what the Hub lacks on the LOCAL     │                                  │
  │ graph (as push_incremental does today)      │                                  │
  │── push: updates + rings + records + pack ──►│ quarantine area                  │
  │                                             │ validate (§4.5)                  │
  │                                             │── accept ───────────────────────►│ store pack, CAS refs,
  │◄─ per-update result, new server op id ──────│                                  │ record server operation
```

**Viewing a closed file in the browser:**

```text
browser UI ──► worker (WASM veil-core, keys) ──► API: fetch tree/objects for my audience
                     │ ◄── ciphertext (+ public objects) ──┘
                     │ open with scope key (unwrapped from the ring with the identity)
                     ▼
         plaintext to the UI for rendering (never to the server)
```

**Anonymous reader:** public renderer → public projection from object
storage. No WASM, no keys, nothing sealed.

---

## 3. Security model and threat model

### 3.1 Trust assumptions

* **Confidentiality of closed content depends only on clients.** The server
  is untrusted for it: content is sealed with AES-SIV under scope keys
  (CRYPTO.md C1); scope keys are HPKE-wrapped to member identities inside
  admin-signed ring changes (C3, C5, C6). None of this changes.
* **Integrity of history and membership depends on signatures**, verified by
  clients: rings replay from the genesis and reject unauthorised changes;
  snapshot ids commit to signatures; embargo records are signed
  (ARCHITECTURE.md §3).
* **The server is trusted for**: availability; freshness (that it shows the
  latest rings, tags and pushes); metadata confidentiality; server-side
  access control on ciphertext and metadata (defence in depth); delivering
  an honest web client to users who do not pin it (§9.5); and, in escrow
  mode only, the release service for embargo timing.
* **Out of scope**: a compromised device that holds keys; coercion of a
  member; side channels in browsers.

### 3.2 Attackers

| Attacker | Can | Cannot | Mitigations and residual risk |
|---|---|---|---|
| **Compromised Hub server** (or a malicious operator, or a lawful-access order served on it) | Read all metadata (§3.3). Deny service, drop or delay pushes. **Equivocate**: show different users different tags, or withhold ring changes (a freshness or rollback attack). **Substitute identities** in the account directory and in invitations. **Serve a malicious web client** that steals keys and plaintext (§9.5). Move tags to any existing, validly signed snapshot (a tag is an unsigned `{target, cloak}` in the view, `Tag` in `oplog.rs`). Learn access patterns | Read closed content or sealed descriptions, comments and logs held only as ciphertext; forge ring changes, snapshot signatures, approvals, CI statuses or embargo records; release an embargo early (except escrow mode); widen visibility of sealed content | Freshness: ring checkpoints and gossip (§6.6), signed tag updates (§4.6). Identity substitution: out-of-band invitation codes (§6.3), fingerprints in the UI, key transparency later (§10). Web client: native clients for sensitive scopes, signed reproducible builds, pinning extension (§9.5). **Residual:** a hub that serves malicious JS once to a user without the extension wins that user's keys; metadata is the operator's |
| **Malicious scope admin** | Read the scope; grant anyone, including other identities of their own; revoke everyone else (a sole rogue admin, docs/BACKLOG.md "Scope governance"); rotate | Read other scopes; forge history signed by others; hide that they did it (the ring log is signed and append-only) | Optional governance (§6.7): minimum admins, two-admin approval for admin revocations, break-glass recovery identity. Recovery without them: re-key into a new scope (the owner's accepted baseline) |
| **Malicious org owner** (Hub-level role, not a scope admin) | Change Hub ACLs (deny access, add accounts to teams), see the org's metadata, delete repositories | Grant scope keys: only a scope admin's client can wrap a key (`Keychain::grant_role`, `keychain.rs`) | Org owner and scope admin are separate roles by design (§6.1). Adding someone to a team mapped to a scope only creates a *grant request* that a scope admin must act on |
| **Malicious member** | Read and exfiltrate their scopes; push validly signed junk; release an embargo of their scope early (any key holder can, `Keychain::release_embargo`); publish cloaked content with `vl merge` (scanned) or `vl expose` | Grant, revoke or rotate; read other scopes; push to protected tags without the required approvals (server rule); change the audience of sealed files through `.veilpolicy` (refused by merge and import, ARCHITECTURE.md §5) | Protected tags require PR approval for declassification (§5.6). Exfiltration of what they could read is not preventable; offboarding lists what to rotate (§6.5) |
| **Outside contributor** | Read the public projection; open PRs; push snapshots to their PR namespace | See or edit sealed files. An edit of a file they cannot seal is held back by their own `vl` (`BuildReport::cloak_failures`, ARCHITECTURE.md §4 rule 4); sealed entries they cannot read are carried over by id (rule 6) | Server rejects new sealed objects from non-members (§4.5). A `.veilpolicy` change in their PR needs approval from the scopes it touches (§5.6) |
| **Network attacker** | Observe traffic sizes and timing | Read or modify traffic: TLS (HTTPS) or SSH; every request is also signed by an identity and bound to the Hub origin and a nonce (§4.3), and all closed content is sealed end to end | Residual: traffic analysis |
| **Compromised web client** (malicious build served, XSS in the app origin, malicious extension) | Everything the user's web identity can do while the page is open: unwrap their scope keys, read plaintext, sign approvals, comments and, if the identity is an admin, ring changes (grant the attacker) | Use keys of identities that never entered the browser (native-only identities) | Web identities are separate device identities (§9.3); orgs can keep admin roles and sensitive scopes native-only; repository content never renders in the app origin (§9.6); CSP, Trusted Types. **Residual:** a compromised browser session is a compromised member for those scopes |
| **Compromised CI runner** | Read the scopes it is a member of and the CI secrets granted to it | Other scopes | Narrow CI scopes, ephemeral runners, revoke and rotate on compromise (§7) |

### 3.3 Metadata the server necessarily sees

Today, a team remote already holds all of this; the Hub adds account-level
data and access logs. "Today" cites the current formats.

| Metadata | Visible to the Hub? | Source today | Can it be reduced? |
|---|---|---|---|
| Accounts, emails, IP addresses, session times | Yes | (new with the Hub) | Data minimisation, retention limits |
| Who pushed, fetched or viewed which repository and which objects, when | Yes | (new) | Partly: fetch whole audience partitions (§4.7), not single objects |
| **Names of cloaked files**, directory structure, sizes | **Yes, today** | Tree entries are plaintext: name, size, tier, label (FORMAT.md §3.2); "File names, sizes and tree shape of cloaked files are visible" (ARCHITECTURE.md threat model) | Yes: sealed directory nodes (ARCHITECTURE.md roadmap). Needed before GA (§10.1) |
| Ciphertext sizes and object counts | Yes | `veil:sea2` length = plaintext length + 16 + label | Size padding (§10.1) |
| Equality of sealed content under the same scope | Yes | Deterministic sealing (CRYPTO.md C1, "Equality leaks") | No: determinism is required for dedup and no-op snapshots; it also powers §5.6 |
| Which entries changed between two snapshots, and their scope | Yes | Object ids in trees | Sealed trees reduce this to "something under this sealed directory changed" |
| Scope names | Yes | Envelope labels `<scope>#<key-id>` (CRYPTO.md C1); embargo records | Opaque scope ids with sealed display names (§6.1) |
| Scope membership: member ids, **member names**, roles, generations, the full membership history | Yes | Rings are plaintext signed logs; `MemberGrant.name` is plaintext (`keychain.rs`) | Partly: names could be sealed under the scope key (ring format change). Ids are needed by the server for access control anyway |
| Snapshot metadata: parents, change id, author string, timestamp, predecessors, signer, the `cloak` scope, the `embargo` id, conflict paths | Yes | `Snapshot` (`object.rs`); descriptions may be sealed (`Text::Sealed`) | Little. Conflict paths are already not recorded on embargoed lines (ARCHITECTURE.md §7 step 5) |
| Embargoes: existence, scope, deadline, creator, merge parents | Yes | ARCHITECTURE.md threat model, "Embargo metadata that remains visible" | No (by design the merge is visible) |
| PR metadata: who opened, reviewed, approved what, when; which scopes a PR touches; comment counts and sizes | Yes | (new) | PR title and body can be sealed (§5.2) |
| CI: job timing, runner, result, log size | Yes | (new) | Results could be sealed; timing cannot |
| Web-client usage: which files a user opened | Yes, unless whole trees are prefetched | (new) | Prefetch by audience partition (§9.7) |

### 3.4 Comparison

| | GitHub | Proton-style end-to-end web apps (Proton Mail and Drive, Tresorit, the 1Password and Bitwarden web vaults) | Veil Hub |
|---|---|---|---|
| Server reads content | All of it | No | Public projection only |
| Access control enforced by | The server alone | Cryptography, plus the server for metadata | Cryptography for closed content; the server for metadata and as defence in depth |
| Server-side features (search, code navigation, secret scanning, AI) | All content | None, or only on metadata | Public projection only; closed content client-side |
| Code-delivery risk (server serves the client) | Not applicable: the server is trusted anyway | **The main residual risk**; mitigated by native apps, open-source clients, and in WhatsApp Web's case a verification extension (Meta's Code Verify) | Same problem, same mitigations (§9.5), plus native-only scopes |
| CI secrets | Encrypted to a repository key the server holds, decrypted by GitHub to inject | Not applicable | Sealed to runner identities; the Hub never holds them (§7) |
| Security advisories | Temporary private forks; GitHub sees the fix | Not applicable | Embargoed merges; the Hub sees ciphertext and metadata only (§8) |
| Revocation | Immediate (server-side) | Key rotation, forward-only | Server-side ACL immediately, key rotation forward-only |
| Metadata | Everything | Varies; usually who, when, sizes | §3.3: who, when, sizes, tree shape, scope names, membership |

---

## 4. The smart sync protocol

The 1.0 decision was "no custom network protocol": SFTP and paths are
"dumb" transports, and the client does all the work (`remote.rs`). The Hub
needs a smart protocol for three things a dumb transport cannot do:

1. **Server-side validation before anything becomes visible.** Today a push
   writes packs, rings and the operation straight into the remote's
   `.veil/` under a fencing lease; a hostile pusher can write anything, and
   readers reject it when they pull (ARCHITECTURE.md §8).
2. **Server-enforced permissions on metadata**: who may move which tag, who
   may push ring changes, what reaches the public projection.
3. **Atomic, per-viewer serving**: compare-and-swap on refs (SFTP has none;
   the fencing lock's residual risk is a holder stalled "between its final
   check and the single `op_head` write", ARCHITECTURE.md §9), and packs
   filtered by audience.

The protocol keeps Veil's sync semantics exactly: the same objects, the same
canonical encodings, the same pack format, the same ring and embargo merge
rules, the same tag fast-forward rules. Only who runs the checks, and
where, changes.

### 4.1 Transports and framing

* **HTTPS** (HTTP/2): `POST https://hub.example/v1/repos/{org}/{repo}/rpc/{name}`.
* **SSH**: `ssh hub.example vl-serve {org}/{repo}`, the same frames over
  stdin and stdout. This also gives a self-hosted **`vl serve`**: a team
  server with `vl` installed gets server-side validation without the Hub.
  `vl` probes for `vl-serve` on an `ssh://` remote and falls back to SFTP
  when it is absent, so today's SSH remotes keep working unchanged.

Both carry the same frames:

```text
frame    = len u32be | type u8 | payload[len - 1]
type     0x01 control    payload = one JSON object (serde_json, as everywhere in Veil)
         0x02 pack-data  payload = raw bytes of a VEILPAK1 pack (a pack may span frames)
         0x03 progress   payload = JSON {phase, done, total}
         0x04 error      payload = JSON {code, message, retry_after_ms?}
         0x05 end        payload = empty
limits   control frame ≤ 1 MiB; pack-data frame ≤ 4 MiB; 1 control frame per message
```

Packs on the wire are the on-disk format (ARCHITECTURE.md §10): `stored`,
`zstd` and `delta` entries, each object re-hashed against its id on read.
Today sync already sends packs (`PackBuilder`, `PackSink` in `remote.rs`);
the protocol only changes who writes the index.

### 4.2 Messages

```text
hello        C→S {protocol: 1, client: "vl 1.4.0", repo_format_max: 3, features: [...]}
             S→C {protocol: 1, repo_format: 3, features: ["audience-filter", "resumable-upload",
                  "pr-refs", "signed-tag-updates"], limits: {max_pack: 2147483648, ...},
                  challenge: "<32 random bytes, hex>"}

ls-view      C→S {}
             S→C {op: "<server op id>", audience: ["public", "team", "ops"],
                  tags: {"main": {target: "<id>", cloak: null}, "notes": {target: "<id>", cloak: "team"}},
                  heads: ["<id>", ...],
                  rings: [{scope: "team", seq: 7, head: "<chain hash>"}, ...],     // audience scopes only
                  embargoes: [{id: "77932133a2", hash: "<blake3 of record>"}, ...],
                  pr_refs?: {...}}                                                 // §5.1

fetch        C→S {want: ["<tag target>", ...] | "all-tags", have: ["<snapshot id>", ...],
                  rings: {"team": 7}, embargoes: {"77932133a2": "<hash>"}, full: false}
             S→C progress*, pack-data*, control {rings: [KeyRing...], embargoes: [EmbargoRecord...],
                  redacted: 12, withheld: 3}, end

upload       C→S {sum: "<pack blake3>", len: 2600000}              → S→C {upload: "<id>", offset: 0}
             C→S pack-data* (HTTP: PUT /v1/uploads/{id}, Content-Range for resume)

push         C→S {expected: {"main": "<old>", "fix": null},      // per-tag compare-and-swap
                  updates: [{tag: "main", new: "<id>", cloak: null, force: false,
                             signed: <TagUpdate>}],              // §4.6, optional at first
                  rings: [KeyRing...], embargoes: [EmbargoRecord...],
                  pack: {upload: "<id>"} | inline pack-data frames}
             S→C {op: "<new server op id>",
                  results: [{tag: "main", status: "ok"} |
                            {tag: "fix", status: "rejected", code: "non-fast-forward", message: "..."}],
                  warnings: [...]}
```

Names, ids and records are the existing types (`Tag` in `oplog.rs`;
`KeyRing`, `EmbargoRecord` in `keychain.rs`; ids are hex BLAKE3). Rings and
records travel whole, as files do today; the Hub may later send only
missing ring changes (`seq > n`).

### 4.3 Authentication

Three credentials, for three different jobs. None of them is a content key.

| Credential | Used by | Proves | Notes |
|---|---|---|---|
| **Veil identity signature** (Ed25519 signing key of a `veil1…` identity, CRYPTO.md C4) | `vl`, runners, the web client's worker | "this request comes from identity X", and through the account directory, from account A | The primary credential for the protocol. The identity must be registered to the account (§6.2) |
| **SSH key** | `vl` over `ssh://` | Transport login, as on any SSH server | Registered to the account like on GitHub; the identity signature is still required for writes |
| **WebAuthn passkey** | Browser login | Account login; with the PRF extension, also unlocks the browser's stored identity (§9.3) | Session cookie: `HttpOnly`, `Secure`, `SameSite=Strict` |

Request signing (HTTPS) or channel binding (SSH):

```text
Veil-Auth: v1 id=veil1<x25519 hex> key=<ed25519 hex> ts=1730700000000 nonce=<16 bytes hex> sig=<hex>

sig = Ed25519(signing key, SIG_PREFIX ‖ "hub-request" ‖ 0x00 ‖
              JSON {hub: "hub.example", method: "POST", path: "/v1/repos/acme/app/rpc/push",
                    body: "<blake3 of the body>", ts, nonce, challenge?})
```

* A new signature context `hub-request` in `crypto/domains.rs` (CRYPTO.md
  §3 requires every domain string to live there); it cannot collide with
  the snapshot, ring or embargo contexts.
* The server accepts `ts` within ±5 minutes and remembers nonces for 10
  minutes. Over SSH, the `hello` challenge is signed once per connection.
* For long transfers, the first signed request returns a session token (1
  hour, bound to the identity and the repository).

Transport authentication only decides what the server *sends*. The
authenticity of content is still checked by clients from the signatures
inside it, whoever served it.

### 4.4 Negotiation

Veil views are small: tags, heads and workspaces (`View`, `oplog.rs`), so
negotiation can be one round trip in the common case.

* **Fetch.** The client sends as `have` the tips of its committed view (its
  tags, remote tags and heads). The server keeps the tips it knows, walks
  their closure on its own graph (the same "committed view is a complete
  closure" rule, `remote::committed_closure`), and sends every object
  reachable from `want` outside that closure, filtered for the viewer's
  audience. A client with thousands of tips sends them in batches; the
  server answers `known: [...]` per batch, as Git protocol v2 does with
  `have` lines (the idea, not the protocol).
* **Push.** As today, the client decides: it reads the server's view
  (`ls-view`), walks the closure of the server's tips on its *local* graph
  and builds one pack of what lies outside it (`push_incremental`). The
  server then checks closure on its side (§4.5), so a client that guessed
  wrong gets a precise `missing: [...]` error and resends.
* **Embargoed merges.** The rule for redacted parents carries over: an
  embargoed merge's non-first parents count as present only if the server
  holds them (`committed_closure`'s `parent_ok`).
* **`--full`.** `vl push --full` / `vl pull --full` keep their meaning
  (re-verify everything); on the protocol, `full: true` disables the closure
  shortcut and the server sends or accepts every object.

### 4.5 Push validation

The server runs these checks in a quarantine area, in this order, before
anything becomes visible. Most are the checks a pulling client runs today;
running them on the server rejects bad data once, for everyone. **They must
be the same code** (§10.1): a server that accepts what clients reject, or
the reverse, splits the repository.

| # | Check | Today, on the client | Server can check without keys? |
|---|---|---|---|
| 1 | Authorisation: the account may push to this repository; each tag update is allowed by the tag's protection rules (§5.6) | none (SFTP permissions only) | yes |
| 2 | Pack integrity: trailer and index checksums, every object re-hashed against its id | `Pack::get`, `verify_packs` (`pack.rs`) | yes |
| 3 | Canonical decoding of every tree and snapshot; safe names (`..`, `/`, NUL, `.veil` in any case refused); depth ≤ `MAX_TREE_DEPTH` (1,024) | `Object::decode`, `Transfer::copy` (`remote.rs`, ARCHITECTURE.md §2) | yes |
| 4 | Objects allowed by the repository format (`veil:sea2` and binary trees not in format 1/2, …) | `ObjectStore::check_storable` | yes |
| 5 | Closure: every object referenced by the new tips is in the pack or already stored, except permitted redactions (the non-first parents of an unreleased embargoed merge) | the closure walk of pull | yes |
| 6 | **Sealed-object authorship**: a *new* object sealed under `S#k` is accepted only from an identity that is a member of `S` at generation `k` (by ring replay), and one sealed under `embargo/<id>` only from a member of that embargo's scope. Carried-over sealed entries (existing ids) are always fine | none: a team remote accepts any ciphertext, and readers get `Redacted`/`Corrupt` | yes (cannot check that the ciphertext *opens*; it can check who wrote it) |
| 7 | Snapshot signatures verify (`Snapshot::unsigned_id`, C5). Per-tag policy: "signer must be a known member" or "signer must be the pusher" | reported by `vl log`, not enforced ("signatures are advisory") | yes |
| 8 | Rings: `KeyRing::verify()` (chain, signatures, admin authorisation, rotation wraps exactly the remaining members, bindings) and fast-forward only (`Keychain::merge_ring`); optional governance rules (§6.7) | `merge_ring` on pull | yes, except the **genesis proof** (needs the generation-0 key; "Rings on a non-member remote cannot check the genesis proof", ARCHITECTURE.md threat model). Members still check it |
| 9 | Embargo records: creation signed by a member of the scope; signed fields immutable; a published key matches `key_id` | `Keychain::merge_embargo` | yes |
| 10 | Tags: fast-forward unless `force` and the pusher may force; valid names (`validate_tag_name`); target is a snapshot | `push_with` (decided on the pusher's local graph today) | yes, on the server graph |
| 11 | Tags that would publish withheld history (a tag on an embargoed fix, or on a commit building on it) are refused for the public projection | `push_closure` skips them with a reason | yes (`embargo_withheld` is key-independent) |
| 12 | **Pre-publish gate**: blobs that become *newly public* through this push (newly reachable from a tag in the public projection, including content declassified by a merge or released by an embargo) are run through the secret scanner (`secrets.rs`); a hit rejects the update, or quarantines it for review, by repository setting | the builder scans public files before snapshotting; `vl scan` | yes: public content is plaintext |
| 13 | Quotas and limits (§4.8) | none | yes |

Then the repo worker commits: it moves the pack into storage, applies
rings and records with the existing merge functions, and updates refs with
a compare-and-swap against `expected` in the metadata DB. Each accepted push
is recorded as one **server operation** (the remote's own op log, as a push
writes one today: `remote.transaction("push from …")`), whose `user` is the
authenticated account and identity. The web UI's "op log" for a repository
is this push log. Members' own op logs stay device-local, as now (FORMAT.md
§2: operations are not synced).

Check 12 implements the "pre-publish gate" requirement: it is enforceable
only because the Hub is then the one path to the public projection and to
the Git mirror (§5.8). A client-side hook alone can be bypassed.

### 4.6 Signed tag updates (freshness of refs)

Tags are unsigned today (`Tag { target, cloak }` in `oplog.rs`): a remote's
view says where `main` points, and a client fast-forwards local tags from it
(ARCHITECTURE.md §8). A malicious
Hub could therefore point `main` of a *fresh* clone at an old, validly
signed snapshot. Proposal:

```text
TagUpdate = {repo: "<repo_id>", tag: "main", old: "<id>" | null, new: "<id>", cloak: null,
             seq: 41, at: 1730700000000}
signature: Ed25519(identity, SIG_PREFIX ‖ "tag-update" ‖ 0x00 ‖ JSON TagUpdate)
```

The Hub stores the chain of updates per tag and serves the latest with
`ls-view`. `vl` verifies the chain and that each signer was allowed (a
member of the repository's maintainers, published as a signed repository
policy). Clients that have seen `seq 41` refuse `seq 40`. This is Hub
metadata first (no format change); it can move into the engine's view
later.

### 4.7 Serving by audience

* An **audience** is the set `{public} ∪ {scopes the viewer is a member of
  in the current ring} ∪ {embargo/<id> for unreleased embargoes of those
  scopes} ∪ {released embargoes}`.
* The filter generalises `Transfer::allowed` from a boolean `public` to an
  audience set. Rings are sent only for scopes in the audience (a
  generalisation of "public remotes receive no rings", BUG-077).
* **Audience-partitioned packs.** The repo worker stores objects in packs
  per label class (public, `team`, `ops`, `embargo/…`), so a fetch serves
  whole existing packs (immutable, cacheable, resumable with `Range`)
  instead of building one per viewer. Sealed objects are stored as-is
  anyway ("ciphertext does not compress", ARCHITECTURE.md §10), so
  partitioning loses no deltas. A released embargo's packs move to the
  public class.
* Tree entries a viewer cannot open still name the file and its size (until
  sealed trees). The server cannot hide those without breaking tree ids;
  sealed trees fix this (§10.1).
* Server-side filtering is defence in depth. A revoked member who cloned
  before keeps what they had; a member removed from a team at the Hub
  stops receiving new ciphertext at once, before any rotation.

### 4.8 Rate limits and quotas

| Limit | Default | Why |
|---|---|---|
| Requests per identity / per IP | 60 / s burst, 5,000 / h | abuse |
| Concurrent pushes per repository | 1 being validated, 4 queued | serialised writer |
| Pack size per push | 2 GiB (larger: split by the client) | memory; the engine builds sync packs in memory today (ARCHITECTURE.md roadmap) |
| Objects per push | 1,000,000 | validation time |
| Single object | 4 GiB | the same ceiling SFTP has (`VEIL_SFTP_MAX_FILE`) |
| Tree depth | 1,024 | `MAX_TREE_DEPTH` |
| Ring log length | 100,000 changes | replay cost |
| Validation CPU per push | 120 s | hostile input |
| Storage per org | plan-dependent | ciphertext does not deduplicate across scopes |

`error` frames carry `retry_after_ms`. Unauthenticated fetches of the
public projection have their own, lower limits.

### 4.9 Resumability

* **Uploads** are sessions (`upload`), resumable by offset (HTTP
  `Content-Range`, or a `resume {upload, offset}` control frame over SSH),
  identified by the pack's BLAKE3 sum, kept 24 hours. Validation starts
  only at `push`, so a broken upload never leaves anything visible.
* **Downloads** of existing partitioned packs are plain ranged GETs of
  immutable files. Server-built packs are cached by `(want, have, audience)`
  for an hour, so a retried fetch resumes.
* Crash safety on the server keeps the engine's ordering: objects, barrier,
  then refs (ARCHITECTURE.md §9). A crash leaves an invisible pack at worst.

### 4.10 How path and SFTP remotes keep working

* **Nothing changes for them.** `remote::push` and `remote::pull` over any
  `StorageBackend` stay the default for paths and SFTP. The smart transport
  is a second implementation of the same contract (`SyncReport`, the same
  filters and merges), selected by URL:

  | URL | Transport |
  |---|---|
  | `../hub`, `/mnt/share/proj` | path (`DiskBackend`) |
  | `alice@host:repo`, `ssh://host/repo` | `vl-serve` over SSH if the server runs it, else SFTP (`SftpBackend`) |
  | `hub:acme/app`, `https://hub.example/acme/app` | smart, HTTPS |

* **Migration** is a push: `vl remote add hub hub:acme/app && vl push hub`.
  Rings, embargo records and history move with it, and the Hub validates
  everything on the way in. A team can keep its SFTP remote as a mirror
  (`vl push origin && vl push hub`).
* The Hub does not offer SFTP write access: it could not validate a push
  that writes files directly.

---

## 5. Pull requests and review on change ids

### 5.1 Data model

```text
PullRequest {
  number: u64,                          // per repository
  target: "main",                       // a tag
  author: {account, identity},
  audience: Public | Scope("sec"),      // who may see that the PR exists (server-enforced)
  title, body: Text,                    // Plain, or Sealed under a scope (as snapshot descriptions)
  stack: [ChangeId],                    // bottom first; the changes under review
  revisions: [Revision],
  state: Open | Merged {target_after: SnapshotId, merged_by, at} | Closed,
  rules: RuleSnapshot,                  // the protection rules in force (§5.6)
}

Revision {                              // one per push to the PR
  n: u32,
  base: SnapshotId,                     // target tip the stack was built on
  heads: {ChangeId → SnapshotId},       // each change's snapshot at this revision
  pushed_by, at,
  touched: {"public": [...], "ops": [...], "embargo/77…": [...]},   // computed by the server, §5.3
}

ReviewThread  { id, anchor: Anchor, state: Open | Resolved, comments: [Comment] }
Comment       { id, author, at, body: Text /* Plain | Sealed */, signature }
Approval      { signed statement, §5.6 }
```

* **PR heads are server-side refs** (`pr/<n>/<change id>`), not view tags.
  They are roots for the Hub's gc and appear in `ls-view` only on request
  (`pr_refs`), so they never clutter members' views. Pushing to a PR is a
  `push` whose updates name `pr/42` instead of a tag.
* **Revisions follow change ids.** A rebase gives each change a new
  snapshot id with the same change id (ARCHITECTURE.md §5), so the PR maps
  it to the same entry in `stack`; `predecessors` (the evolution log) links
  the new snapshot to the old. Changes added to the stack, abandoned or
  squashed away are shown as such between revisions.
* Approvals, comments and statuses are signed statements stored in the DB
  and exportable as a bundle. They are not Veil objects in 1.x. Whether
  review records should travel with the repository is an open question
  (§11.1).

### 5.2 One PR, different viewers

A PR from Alice touches `app.py` (public), `deploy/prod.yml` (cloaked
`ops`) and `secrets/notes.md` (cloaked `team`):

| Viewer | Sees in the PR | How |
|---|---|---|
| Anonymous / outside contributor | The `app.py` diff; "2 files in scopes you are not a member of changed" with names and sizes (today's tree metadata) or, with sealed trees, only "changes in 2 closed areas" | Server: public projection only; the diff is server-rendered |
| Team member, not in `ops` | `app.py` and `secrets/notes.md` diffs; `deploy/prod.yml` as "changed, scope `ops`, no access" | Web client fetches public + `team` ciphertext, decrypts `team` in the worker |
| `ops` and `team` member | Everything | Web client |
| Hub operator | The `app.py` diff, all names and sizes, ciphertext for the rest | (what the server holds) |

The PR's **title and body** follow snapshot descriptions: plain by default,
sealed if the author chooses a scope, and sealed automatically when the
top change's description is sealed (a PR from a cloaked workspace, whose
descriptions are sealed for its scope, ARCHITECTURE.md §4 rule 4). A PR
with `audience: Scope(S)` is hidden by the server from everyone outside
`S`: its existence, number and metadata (the security-fix case).

### 5.3 What the server computes: touched scopes

For each change, the repo worker diffs the change's tree against its
parent's **by object id**, without keys: an entry whose id changed, appeared
or disappeared is touched, with its label (public, `S`, `embargo/<id>`).
With sealed directories, a changed sealed directory counts as "something in
`S` changed", which is all approval routing needs. The union is
`Revision.touched`, which drives approval requirements (§5.6) and what each
viewer is told.

`.veilpolicy` changes are flagged separately: a policy edit that would
change the audience of sealed files is not taken by `vl merge` anyway
(ARCHITECTURE.md §5), but a PR that edits `.veilpolicy` requires an
approval from each scope whose paths its rules mention.

### 5.4 Comments anchored across rewrites

```text
Anchor { change: ChangeId, revision: u32, snapshot: SnapshotId,
         path: Text,                    // Plain, or Sealed under the file's scope
         side: Old | New, lines: [start, end], context: "<blake3 of the anchored lines>" }
```

* Comments on a cloaked file are sealed under that file's scope (current
  generation), with XChaCha20-Poly1305 and a random nonce, exactly like
  sealed descriptions (CRYPTO.md C2), under a **new label prefix**
  `review:<scope>#<key-id>` added to `domains.rs` so a comment can never be
  presented as a description. The anchor's path is sealed the same way
  once sealed trees hide names.
* **Carrying an anchor to a new revision:** if the file's object id is
  unchanged between revisions, the anchor moves as-is, and the server can do
  that itself, even for sealed files (determinism, §2.2). Otherwise the first
  client that can read the file re-anchors it (maps the lines through a diff
  of the two versions and checks `context`), and posts a signed anchor
  update; until then the thread shows "outdated" to everyone.
* Comments are signed by the commenter's identity (`review-comment`
  context), so a server cannot alter or forge them; it can only withhold
  them.

### 5.5 Who can merge without reading everything

Merging is tree-level, and files changed on only one side resolve by id;
only a file both sides changed is read for diff3, and reading a sealed file
without its key fails with "cannot merge … you do not hold the key"
(`merge.rs`, `read_for_merge`). So a maintainer who is not in `ops` can
merge a PR touching `ops` files, as long as `main` did not also change those
files. Otherwise the Hub says that a member of `ops` must merge, or rebase
the PR first.

### 5.6 Approvals per scope, and protection rules

Protection rules, per tag (`main`, `release/*`):

```toml
[tags."main"]
require_pr = true
approvals = { public = 1, ops = 1, team = 1, policy = "per-touched-scope" }
approver_role = "member"          # of the scope; or "admin"
require_signed = "member"         # every new snapshot signed by a known member
require_status = ["ci/build", "ci/test"]
allow_force = false
dismiss_stale = "per-scope"       # see carry-over below
```

An approval is a signed statement:

```text
Approval = {kind: "veil-approval/1", repo: "<repo_id>", pr: 42, revision: 3,
            base: "<snapshot id>", heads: {"<change id>": "<snapshot id>", ...},
            scopes: ["public", "ops"], verdict: "approve" | "request-changes",
            at: 1730700000000}
signature: Ed25519(reviewer identity, SIG_PREFIX ‖ "review-approval" ‖ 0x00 ‖ JSON Approval)
```

* **Who may approve for scope `S`**: an identity that is a member of `S` in
  the ring at the time of the approval, bound to the reviewer's account. The
  server checks this by ring replay; so does every client that merges
  (§5.7), so the server's word is never needed.
* **Approving `public` content** needs the repository's maintainer role, a
  Hub-level permission published in the signed repository policy.
* **Carry-over across revisions.** An approval for scope `S` stays valid for
  revision `r+1` when, for every entry labelled `S` that the PR touches, the
  `(path, object id)` pairs at the base and at the heads are unchanged.
  Deterministic sealing makes this exact for ciphertext: a rebase that did
  not change `ops` files keeps `ops` approvals, while any edit to them
  dismisses only the `ops` approval. Public approvals use the same rule on
  plaintext ids.
* **Approval of what a reviewer cannot read** is impossible by construction:
  the web client signs an approval for `S` only if it decrypted and showed
  the `S` diff. A reviewer can still approve with `--scopes public` alone.

### 5.7 Merge: client-side, then pushed

The Hub never merges: merging closed files needs keys. "Merge" in the web
UI runs in the browser's worker; `vl hub pr merge 42` does the same from the
CLI:

```text
merger's client                                    Hub
  │── fetch PR 42 revision 3, approvals, rules ──────►│
  │◄──────────────────────────────────────────────────│
  │ verify every approval signature and the approver's
  │ ring membership itself; verify statuses (§7.5)
  │ vl merge <heads> --into main [-m] [--embargo --until T --scope S]
  │   (or fast-forward, or rebase: the strategy the rules allow)
  │── push {updates: [{tag: main, new, signed}], pr_merge: 42} ─►│ check: rules satisfied by
  │                                                   │ the approvals for the merged content;
  │                                                   │ the new target contains the approved heads
  │                                                   │ (merge or fast-forward) or their rewrites
  │                                                   │ with unchanged touched entries (rebase)
  │◄── ok, PR 42 merged ──────────────────────────────│
```

* **Embargoed merges** are ordinary client-side merges with `--embargo`
  (ARCHITECTURE.md §7). The PR then has `audience: Scope(S)`, the fix line
  is cloaked under `S`, and the push carries the embargo record. The Hub
  validates the record (§4.5 check 9), keeps the fix's history out of the
  public projection (check 11) and shows the public the pre-merge tree.
  Release is §8.
* The one-embargo-per-line rule applies (ARCHITECTURE.md §7, "Embargoes
  never overlap"): the Hub refuses to queue a second embargoed PR into a
  line that carries an unreleased embargo, with the same message `vl merge`
  gives.
* **Declassification is explicit.** A merge that publishes files from a
  cloaked line (`vl merge` of a cloaked line, secret-scanned, ARCHITECTURE.md
  §5) is labelled in the PR as "publishes N files from scope S" and requires
  an approval for `S` as well as for `public`; the pre-publish gate (check
  12) scans the published blobs on the server too.

### 5.8 The Git bridge

* **The Hub mirrors the public projection to GitHub.** Export is
  deterministic and key-independent: tree, message and parents come from
  the public projection, cloaked descriptions become placeholders, and only
  *released* embargo keys are ever used (ARCHITECTURE.md §11, "Export").
  The Git mirror worker can run `git::export` and `vl git push` server-side
  with no Veil keys, only GitHub credentials. Being the one path to GitHub
  is what makes the pre-publish gate (check 12) enforceable.
* **GitHub PRs from outside contributors** can be imported as Hub PRs:
  import goes through the policy gate on the full Veil tree
  (`git/import.rs`), so a GitHub commit never deletes cloaked files. Two
  limits: the Hub cannot seal, so a GitHub commit that adds a file at a
  cloaked path is held back (as for any reader without the key, ARCHITECTURE.md
  §4 rule 4) until a member imports it; and imported snapshots are signed by
  the Hub's bridge identity, which is a known non-member key, not a member.
* **Hub PRs to GitHub**: only PRs whose touched set is public-only can be
  mirrored as GitHub PRs (a branch per PR). A mixed PR is not mirrored: its
  public half alone would be reviewed out of context. The Hub is the system
  of record for review; GitHub is a mirror plus an inbox for outside PRs.
* A Hub-side `vl git pull` of GitHub-made commits onto `main` is a push
  like any other and passes the same protection rules.

---

## 6. Access control

### 6.1 Orgs, teams and scopes

| Concept | Where it lives | Enforced by | Holds keys? |
|---|---|---|---|
| **Account** | Hub DB | Hub | no |
| **Identity** (`veil1…`, one per device or runner) | the device; the public part in the Hub directory | cryptography | its own secret only |
| **Org**, org owner | Hub DB | Hub | no |
| **Team** (a set of accounts) | Hub DB | Hub (ACL on repositories, PR roles) | no |
| **Scope** (a ring per repository, ARCHITECTURE.md §3) | the repository | cryptography (only members can unwrap) | the wrapped keys |
| Scope admin | the ring (`role: admin`) | ring replay | yes |

* **Org owner and scope admin are different roles.** Org owners manage
  accounts, teams, billing and Hub ACLs; they cannot grant a scope key.
  Scope admins hold keys. A small team will give both roles to the same
  people, but the design never needs an org owner to be a key holder.
* **Teams map to scopes.** A mapping `team "ops" → scope "ops" in repos
  acme/*` means: adding an account to the team creates a **grant request**
  for each of the account's registered identities; removing one creates a
  revocation request. Requests are executed by a scope admin's client
  (the web client or `vl hub sync-grants`), which wraps the key and signs the
  ring change. Until then, the Hub's ACL already gives (or removes) access to
  the ciphertext. The Hub shows the drift between team and ring.
* **Opaque scope names.** Scope names are visible to the server and on
  public remotes (labels, embargo records). The Hub creates scopes with
  opaque names (`s-7f3a9c21`) and keeps the human name sealed under the
  scope key in its DB, unless the org opts for readable names.
* **Scopes are per repository** today (rings live in each repository's
  `.veil/meta/keyrings/`). An org-wide team mapped to the same scope name in
  20 repositories means 20 rings, and 20 admin signatures per change. The
  admin's client batches them (one confirmation, many signed changes); an
  org-level ring shared by repositories is an engine change to consider
  later (§11.1).

### 6.2 Identities and devices

* Each device (laptop, browser, runner) has its own identity, created where
  it is used. The secret never leaves the device.
* An identity is registered to an account with a signed statement:

  ```text
  {kind: "veil-hub-identity/1", hub: "hub.example", account: "alice",
   identity: "veil1<x25519><ed25519><binding>", device: "laptop", kind_hint: "native" | "web" | "runner",
   at: 1730700000000}
  signature: Ed25519(identity, SIG_PREFIX ‖ "hub-identity" ‖ 0x00 ‖ JSON)
  ```

  plus a WebAuthn assertion of the account, so neither the identity nor the
  account can be claimed alone.
* **A new device** needs grants like any new member: the user's existing
  device (if it is an admin) or an admin approves a grant request. A
  "link device" flow, where an existing device sends its *own* identity to
  the new one (HPKE to a one-time key, verified by a short code on both
  screens), is faster but makes device revocation an identity replacement;
  offered as an option, not the default.
* `kind_hint` is self-declared. Org policy "web identities may not be
  admins / may not join scope `prod`" is applied by admins' clients when they
  grant. It is a policy, not a guarantee: a user can import a native
  identity into a browser.

### 6.3 Invitations: the key exchange

The danger is the Hub substituting its own key for the invitee's: the admin
would then wrap the scope key to the Hub. Today the defence is "compare it
by voice or in person if the content matters" ([guide/teams-and-remotes.md](guide/teams-and-remotes.md#onboarding-a-teammate)).
The Hub keeps that property with a secret that never passes through it:

```text
Admin's client                          Hub                         Invitee's client
  K ← 16 random bytes; invite id I
  store (I, K, scope, role) locally
  POST /invites {I, org, repo, scopes, role, expires}      (no K)
  link = https://hub.example/i/I#K ───── out of band: chat, in person ─────►
                                                        URL fragment K is never sent to the server
                                                        identity P (existing, or created now)
                                                        tag = BLAKE3-keyed(derive_key("veil 2026 hub-invite v1", K),
                                                                           I ‖ 0x00 ‖ P)
                                        ◄── POST /invites/I/accept {account, P, tag}
  ◄── notification: I accepted by bob ──
  verify tag with K, verify P's binding (CRYPTO.md C4)
  show "bob, fingerprint 3f2a…"; on confirm:
  vl scope grant <scope> P --name bob   (HPKE wrap, signed ring change)
  push ring change ─────────────────────►  validates (§4.5 check 8), stores
                                                         pull → ring holds a wrap → key → files fill in
                                                         (the clone-then-grant flow, ARCHITECTURE.md §6)
```

* The Hub learns `P` and the tag, never `K`, so it cannot make a valid tag
  for its own key. An invite sent *by the Hub's own email* would show `K`
  to the Hub; the UI therefore copies the link to the clipboard and never
  offers to send it.
* Someone who intercepts the link can accept first. The invite is
  single-use, and the admin sees which account accepted before granting.
* For invitees in person, a 6-word code (about 66 bits) can replace the
  link. The Hub could search a code that short offline from the tag, so this
  variant needs a PAKE instead of the plain keyed hash (§11.3).

### 6.4 Per-file sharing through small scopes

A file is sealed under exactly one scope (`veil:sea2` carries one label), so
"share `deploy/prod.yml` with Carol" cannot add Carol to `ops`'s key without
giving her all of `ops`. The Hub automates the honest alternative:

1. The sharer's client creates a scope `s-<random>` with members
   `ops ∪ {carol}` (all current `ops` members, plus Carol), the sharer as
   admin, and the `ops` admins as admins.
2. It adds a policy rule `deploy/prod.yml cloak s-<random>` in a PR. This
   re-scopes the file, which is a weakening for local working copies until
   accepted (ARCHITECTURE.md §4, "cloaked → another scope"), and needs an
   `ops` approval (§5.3).
3. The Hub keeps the derived scope in step: every later `ops` grant or
   revocation creates a matching request for `s-<random>`.

Limits, stated in the UI: earlier versions of the file stay sealed under
`ops`; Carol sees the file from the re-scoping on; many small scopes mean
many rings. Unsharing is a revocation (forward-only).

### 6.5 Revocation, rotation and offboarding

"Offboard Bob" in the org:

```text
1. Hub (immediately)   suspend Bob's sessions, SSH keys and identities in the org;
                       stop serving him ciphertext and metadata (§4.7).
2. Hub (immediately)   from the rings (plaintext), list every scope in every repository
                       where any of Bob's identities is a member, with the generations he held;
                       create revocation requests; notify each scope's admins.
3. Admin's client      vl scope revoke <scope> <id> for each (rotates, ARCHITECTURE.md §3);
                       one confirmation for the batch; push.
4. Hub                 the rotation list: from the trees (key-independent), every path at the
                       tips of every tag sealed under a generation Bob held, i.e. content he could
                       read that is still current.
5. Admin's client      decrypts those files and runs the secret scanner on them
                       (`secrets.rs`): "credentials Bob had access to: AWS key in deploy/prod.yml,
                       DB password in secrets/db.env, ...". This list never reaches the Hub
                       unless sealed under the scope.
6. Hub                 announcement to the org (and webhook), with what was revoked and when;
                       the rotation list is shared sealed with the scope admins.
```

* Revocation stays forward-only: Bob keeps what he could read ("Rotate the
  underlying secrets", ARCHITECTURE.md threat model). Step 4 is what makes
  rotation practical.
* Step 1 does not depend on any admin being online. Steps 3 to 5 need one.
* A rotation without a revocation (`vl scope rotate`) is available from the
  scope page.
* `vl scope log` becomes the scope page's history, with signers, times and
  generations (the ring log is plaintext and signed).

### 6.6 Freshness of rings

The threat model already lists trust on first use and the "freshness or
rollback attack" a remote can mount by withholding newer ring changes
(ARCHITECTURE.md threat model). With a Hub this is sharper: if the Hub hides
Bob's revocation from Carol, Carol keeps sealing new content under the old
generation, and Bob, colluding with the Hub, reads it. Mitigations:

* **Ring checkpoints.** Each scope admin's client signs, at least daily and
  after every change, `{scope, repo, seq, head, at}` (context
  `ring-checkpoint`). Clients refuse to *seal new content* under a ring whose
  newest checkpoint is older than a configurable window (default 7 days),
  and say why. The Hub can still freeze a ring, but not for long without
  every member noticing.
* **Gossip.** Clients report the ring heads they hold when they push; the
  Hub must show the newest it has received to everyone, and clients compare
  heads with each other through signed statements that the Hub relays but
  cannot forge.
* **Out-of-band pinning** of a ring head at onboarding (the invite flow can
  carry the head hash next to `K`).
* Longer term: make snapshots commit to the ring heads their signer knew
  (an engine format change, §10.1), so a stale writer is detectable from the
  history itself.

### 6.7 Optional governance (org features)

The owner's baseline: a rogue or departed sole admin is handled by
re-keying into a new scope (docs/BACKLOG.md, "Optional: scope
governance"). The Hub offers these as org settings, off by default:

| Feature | Enforced by | Protects against | Cost |
|---|---|---|---|
| **Minimum admins per scope** (e.g. 2) | Hub rejects ring changes that leave fewer; clients warn | Losing the only admin's identity | None |
| **Hold suspicious ring changes** (revoking an admin, demoting one, granting a new admin) until a second admin confirms in the Hub | Hub (rejects the push until confirmed) | A rogue admin acting alone, as long as the Hub is honest and is the only remote | A delay |
| **Two-admin rule in the ring itself**: such changes carry a co-signature, and ring replay requires it | Clients (ring replay); needs a new ring format and signing context | A rogue admin and a compromised Hub | Engine change (§10.1) |
| **Break-glass recovery identity**: an offline identity (paper, hardware token), admin of every scope in the org | Ring (it is an admin) | Every admin lost or rogue | Its compromise is total; store it like a root CA key |
| **`vl scope recover`**: automates the re-key: new scope, same members minus the rogue, re-cloak, push, list secrets to rotate | Client | Rogue admin, without prior setup | History of the old scope stays readable to its members |

The Hub-enforced options are worth having because the Hub is usually the
only remote. They do not survive a compromised Hub, and the UI says so.

---

## 7. CI on closed code

### 7.1 Runners are members

* A **runner** is a machine with its own Veil identity, created on it
  (`vl identity new` in the runner's `VEIL_HOME`; a TPM or cloud KMS later).
  It is registered to the org as `kind_hint: runner`.
* A scope admin grants the runner identity to the scopes the build needs,
  like any member. Organise for this: builds that need `ops` files get a
  runner group in `ops`; nothing else does.
* **Hub-hosted runners** build only the public projection. They are never
  granted to a scope: a runner that the Hub operates and that holds a key
  would break zero-knowledge. Closed CI runs on **self-hosted runners**
  (customer machines or cloud accounts), or later on attested confidential
  VMs (§11.1).

### 7.2 Job flow

```text
Hub (coordinator)                         runner (identity R, member of ops)
  push to main / PR revision
  → job {repo, snapshot S, workflow file path, runner group, job id, trigger}
  ── long-poll dispatch ──────────────────► 1. fetch S via the protocol (audience of R)
                                            2. verify locally (§7.4) that S may run here,
                                               with secrets or without
                                            3. Repo::ephemeral_workspace(S) or a `vl ws exec`
                                               sandbox; decrypts with R's keys
                                            4. run; seal the log under the job's scope
                                               (label `ci-log:<scope>#<key-id>`)
  ◄── upload sealed log, signed status ─────5. status statement (§7.5)
  show status; enforce require_status
```

* The workflow definition is a file in the repository (`veil-ci.toml` at the
  root; never under `.veil`, which is reserved at every depth). If it is
  cloaked, the Hub cannot read it: it queues "run the workflow at `S` on
  runner group `G`", and the runner parses it.
* Ephemeral workspaces are already the primitive for "agent sandboxes and
  parallel CI tasks" (ARCHITECTURE.md §6): O(1) to create, no disk.
* Logs are sealed for the job's scope, so only members read them; the Hub
  stores ciphertext and sees size and timing.

### 7.3 Secret injection

CI secrets are a cloaked file under a dedicated scope, for example
`ci/secrets.env cloak s-ci`, whose members are the runner identities and the
people who manage the secrets. No new store is needed:

* the runner decrypts the file in its sandbox and passes the values as
  environment variables, as `vl run` does with the vault today;
* the sandbox snapshot treats them as `InjectedSecrets`: any new or changed
  file containing one of the values is quarantined
  (`injected-isolated-secret`, ARCHITECTURE.md §4), so a build cannot record
  a copy of a secret into history or an artefact Veil records;
* log redaction: the runner masks the values in the log before sealing it;
* rotation is a commit to that file; revoking a runner is a scope
  revocation.

The Hub never sees a CI secret, unlike GitHub Actions, where secrets are
encrypted to a repository key GitHub itself holds and decrypts to inject.

### 7.4 Keeping the Hub out of the loop

A compromised Hub could dispatch a job for a malicious snapshot to a runner
that holds secrets (a "pwn request"). So the decision whether a job gets
secrets is made by **the runner, from signed data**, with a runner policy
file that lives on the runner, not in the repository:

```toml
[secrets]
# run with secrets only if all of these hold, checked by the runner itself:
snapshot_signed_by = "member"            # signature status `good` (ARCHITECTURE.md §3)
reachable_from_tags = ["main", "release/*"]   # with signed tag updates (§4.6)
or_approved_by = { scope = "ops", count = 1 } # a valid Approval (§5.6) covering S
[no_secrets]
allow = "any"                            # PRs from outsiders: public projection, no secrets
```

The runner verifies rings, signatures, approvals and signed tag updates
itself. A Hub that lies can only cause a job to be refused or to run
without secrets.

### 7.5 Statuses

```text
Status = {kind: "veil-ci-status/1", repo, snapshot: "<id>", workflow: "ci/build",
          result: "success" | "failure" | "error", log: "<blake3 of the sealed log>", at}
signature: Ed25519(runner identity, SIG_PREFIX ‖ "ci-status" ‖ 0x00 ‖ JSON Status)
```

`require_status` in protection rules names workflows *and* the runner
identities trusted for them, so a status from any other identity does not
count. Merging clients verify statuses themselves (§5.7).

---

## 8. Embargo service

### 8.1 What release is today

An embargo key is wrapped under the scope key; the record commits to its
fingerprint and is signed by a member; release publishes the key in the
record, and every reader checks the fingerprint (CRYPTO.md C7,
`Keychain::release_embargo`, `merge_embargo`). Automatic release happens "on
the first `vl` run by a key holder after the deadline", and only for records
whose creation signature is good (ARCHITECTURE.md §3, §7). Nobody but a key
holder can release, and a key holder can release early.

A server that holds no keys therefore **cannot release on time by itself**.
Three modes, chosen per embargo:

| Mode | Who can release | Who can release early | Postponable | Trust |
|---|---|---|---|---|
| **A. Members** (today) | any key holder's `vl` after the deadline; by hand any time | any key holder | yes (until a key holder runs `vl` after the deadline) | the scope's members |
| **B. Escrow agent** | the release service, at the deadline | any key holder; the agent if compromised | yes (a signed postponement by a scope member) | members + the release service |
| **C. Time-lock (drand)** | anyone, once the drand round for the deadline is published | any key holder | **no** | members + the drand network's threshold |

### 8.2 Hub support common to all modes

* **A trusted clock for deadlines.** The Hub runs the deadline worker. In mode
  A it notifies key holders at the deadline ("release now"); their client
  releases and pushes. Clients can also check deadlines against signed
  time from the Hub (Roughtime-style) instead of a local clock that may be
  wrong.
* **Release is a push** of the record with `released_key` (and a release
  signature). The Hub verifies the fingerprint (check 9), moves the
  embargo's packs to the public partition, rebuilds the public projection,
  fills in the withheld history ("same snapshot ids, now readable",
  ARCHITECTURE.md §7 step 6), and triggers the Git mirror: the publication
  commit fast-forwards GitHub (ARCHITECTURE.md §11).
* After release the content is public, so the pre-publish gate scans it then.

### 8.3 Mode B: escrow to a release service

The record gains escrow recipients (embargo record format 2, an engine
change, §10.1):

```text
EmbargoRecord (format 2) += escrow: [{kind: "hpke", recipient: "veil1<release service>",
                                      enc: "<hex>", ct: "<hex>", not_before: <until>}]
```

* The embargo key, HPKE-wrapped (C3) to the release service's identity, with
  `aad = "embargo-escrow:" ‖ id ‖ until` so the wrap is bound to the deadline.
  The creator's signature covers it (a new signed body, so a new signing
  context, per FORMAT.md §4 rule 5).
* The release service is **a separate deployment with a separate operator
  and keys** (an HSM-held identity), not the API server. It sees only
  embargo keys, which become public anyway. A compromise of both it and the
  Hub's storage means early disclosure; a compromise of one alone does not.
* Postponement: a scope member signs `{id, until: new}`; the service honours
  it. A member could equally release early, so this gives them no new power.

### 8.4 Mode C: time-lock encryption

The embargo key is also encrypted to a future round of the drand randomness
beacon with time-lock encryption (tlock: identity-based encryption to the
round, which drand's threshold network effectively releases by publishing
its signature for that round). Once the round is out, *anyone*, the Hub
included, decrypts the key, checks the fingerprint and publishes the
release.

* No single party can release early or withhold the release; a threshold of
  drand operators colluding could release early.
* It cannot be postponed: a deadline is a guarantee, which suits
  coordinated disclosure with a fixed date and does not suit "release when
  the patch is ready".
* Rust implementations exist (for example `tlock_age`); using one adds a
  pairing-based primitive that the crypto review (CRYPTO.md) does not
  cover yet.

### 8.5 Coordinated disclosure

```text
reporter        → private report form: creates a per-advisory scope s-adv-<n>
                   (admin: the security team), invites the reporter (§6.3)
security team   → cloaked workspace in s-adv-<n>; PR with audience s-adv-<n>  (§5.2)
downstreams     → invited to s-adv-<n> as members for the pre-disclosure period
merge           → client-side `vl merge --embargo --scope s-adv-<n> --until T` (mode A, B or C)
advisory draft  → sealed under s-adv-<n> (text, CVE id, affected versions)
release (T)     → embargo released; advisory published; Git mirror pushed;
                   reporter credited; s-adv-<n> members kept or revoked
```

The scope, cloak and embargo use the same scope, as Veil requires for the
fix's history to reach the team remote before release (ARCHITECTURE.md §7,
"Scopes"). The one-embargo-per-line rule still applies: a second advisory
for the same line waits for the first release, or uses a separate line.

---

## 9. The web client

### 9.1 What the engine needs to run in WASM

`veil-core` is backend-agnostic: "nothing above the VFS layer knows a disk
exists" (ARCHITECTURE.md), `MemoryBackend` is meant for "tests, CI, WASM,
agents" (`vfs/mod.rs`), and a WASM build is on the roadmap. A survey of
`crates/veil-core/src` for what would not build or would fail on
`wasm32-unknown-unknown`:

| Item | Where | Problem in a browser | Change |
|---|---|---|---|
| `std::time::SystemTime::now()` | `now_millis` (`lib.rs`), `vfs/disk.rs` | panics on `wasm32-unknown-unknown` | a clock the embedder injects (see `LockContext`, which already carries a clock for tests) |
| `std::time::Instant::now()` | `store.rs` (gc pending cache), `lock.rs`, `vfs/sftp_client.rs` | panics | same |
| threads: `std::thread::scope` in `par_map` | `remote.rs` | no threads without cross-origin isolation | single-threaded path when `threads == 1` exists; make it the WASM path |
| lock heartbeat thread, `std::process`, `libc` | `lock.rs` | none of these exist | a no-op lock for single-writer in-memory repositories |
| `std::fs`, `libc` | `vfs/disk.rs`, `lock.rs` | none | `DiskBackend` behind `cfg(not(target_family = "wasm"))` |
| SFTP backend (spawns `ssh`, threads) | `vfs/sftp*.rs` | none | behind a feature |
| `gix` | `git/` (feature `git`) | not needed in the browser | `--no-default-features` |
| `zstd` (C library via `zstd-sys`) | packs (`pack.rs`) | builds for WASM only with a C toolchain for that target; large | try `zstd-sys` for WASM first; fall back to a pure-Rust decoder (dictionary support needed for delta entries) and have the browser write `stored` entries (pack kind 0) when it pushes |
| `getrandom` | `crypto.rs`, `identity.rs` | needs its WebCrypto (`wasm_js`) backend enabled for this target | build configuration |
| AES (AES-SIV) without AES-NI | `aes-siv`, `aes` | software AES: slower, constant-time bitsliced in RustCrypto | measure; WebCrypto has no AES-SIV, and composing one from WebCrypto's AES-CBC and AES-CTR would be a homemade construction, which Veil does not do (CRYPTO.md §1) |

Everything else (store, packs, trees, merge, embargo resolution, keychain,
HPKE, Ed25519, BLAKE3, the secret scanner, policy) is plain Rust over
`StorageBackend`. A CI job running `cargo check --target
wasm32-unknown-unknown -p veil-core --no-default-features` keeps it that way
(§10.1).

### 9.2 Structure in the browser

```text
main thread (UI, TypeScript)  ◄── postMessage: rendered plaintext, never keys ──►  Web Worker
                                                                                    ├ veil-core (WASM)
                                                                                    ├ identity, scope keys (memory only)
                                                                                    ├ StorageBackend over OPFS
                                                                                    │   (FileSystemSyncAccessHandle:
                                                                                    │    synchronous, workers only)
                                                                                    └ protocol client (fetch)
user content origin (sandboxed iframe, separate site, no keys): rendered Markdown, notebooks, HTML
```

* **The engine is synchronous** (`StorageBackend` takes `&self` and returns
  data). In a dedicated worker, OPFS sync access handles give synchronous
  file I/O, so an `OpfsBackend` mirrors `DiskBackend` closely.
* **Network reads are asynchronous.** The worker fetches whole audience
  partitions or the closure of a snapshot *before* running engine
  operations over local storage (fetch, then compute), as `vl pull` does
  today. A lazily loading `StorageBackend` that blocks on the network needs
  `SharedArrayBuffer` and `Atomics.wait`, which need cross-origin isolation
  (COOP and COEP headers); the Hub can set those, so this is an option for
  very large repositories.
* Keys and plaintext never reach the main thread except the plaintext being
  displayed.

### 9.3 Key storage in the browser

| Option | Protects against | Does not protect against | Verdict |
|---|---|---|---|
| Identity secret in IndexedDB, plaintext | nothing | anything that reads the origin's storage | no |
| **WebCrypto non-extractable keys** (Ed25519 and X25519 are in WebCrypto in current engines; check minimum versions when implementing) | copying the identity secret out (XSS, a malicious build) | *using* it while the page runs: a malicious script can call `sign` and `deriveBits` as an oracle; and HPKE runs in Rust (`hpke` crate), so the X25519 step would have to be split out of it, while every unwrapped **scope key** lives in WASM memory anyway | useful for the signing key; not a boundary for scope keys |
| **Identity encrypted at rest under a passkey** (WebAuthn PRF extension → a wrapping key; the identity is decrypted into the worker on unlock) | theft of the stored identity without the passkey; a stolen laptop | a malicious script during an unlocked session | **default**; auto-lock after inactivity; PRF support depends on browser and authenticator, with a passphrase (Argon2id) as fallback |
| No stored identity: a one-time "session identity" granted per session | long-term key theft | anything in-session; it needs an admin per session | for kiosks and one-off reviews |

The browser's identity is its own device identity (§6.2), never the user's
laptop identity copied in. It can be revoked alone, kept out of admin roles
and out of sensitive scopes by org policy.

### 9.4 What the web client does

History, trees, file view, diffs and blame-free annotations, conflict
markers (Veil records conflicts as markers in files, ARCHITECTURE.md §5),
scopes and ring logs, embargo state, PR review and approval signing, ring
changes for admins (grant, revoke, rotate) and the client side of merges.
Syntax highlighting (tree-sitter in WASM) and search run in the worker over
decrypted content. A search index of closed content is stored in OPFS,
sealed under a device-local key, never uploaded.

### 9.5 The hard problem: the Hub serves the client

A compromised Hub, or one ordered to, can serve a web client that sends
keys and plaintext to it. No mechanism inside the page can fully prevent
this, because the page is what is compromised. The mitigations, layered:

1. **Native and desktop clients for sensitive work.** `vl` is already the
   full client. A desktop app packages the *same* web client, signed and
   installed (updates verified against the release signature, not fetched
   from the Hub). Orgs can mark scopes **native-only**: admins' clients
   refuse to grant identities registered as `web` to them, and admin roles
   are native-only by default.
2. **Signed, reproducible builds.** Every web-client release is built
   reproducibly from a tagged commit; a manifest lists the BLAKE3 and
   SHA-256 of every asset (HTML, JS, WASM, CSS); release keys separate from
   Hub operations sign it, and it is logged in a public transparency log
   (Sigstore's Rekor or similar). Anyone can rebuild and compare.
3. **A pinning extension** (in the spirit of Meta's Code Verify for WhatsApp
   Web): it fetches the signed manifest from the transparency log, not
   from the Hub, checks every script, module and WASM file the page loads
   against it, and blocks the page and warns on a mismatch. It needs no
   trust in the Hub at all.
4. **Subresource integrity** on every script and the WASM module (`integrity`
   attributes, and `WebAssembly.compileStreaming` only after a hash check).
   SRI protects against a compromised CDN or asset store. It does **not**
   protect against the Hub's origin, which serves the HTML that holds the
   hashes; it is worth having, and must not be presented as more.
5. **A strict page**: CSP without `unsafe-inline` or `unsafe-eval` (WASM
   needs `wasm-unsafe-eval` only), Trusted Types, no third-party scripts, no
   analytics, `Cross-Origin-Opener-Policy`, a pinned service worker that
   refuses unexpected script updates (it helps after first use only, and a
   server can eventually replace it).
6. **Later**: signed web bundles (Chrome's Isolated Web Apps) remove the
   origin from the trust chain where the browser supports them.

**Residual risk, stated plainly.** A user without the extension who loads
the web client from a compromised Hub can lose every key that browser
identity can unwrap, once, without noticing. Transparency logging makes a
*mass* attack detectable after the fact; a *targeted* one-time attack is not
detectable without the extension. That is why the browser identity is
separate, revocable and restricted, and why sensitive scopes should be
native-only.

### 9.6 Repository content is hostile

Outside contributors control file contents, names and descriptions. Any
script running in the app's origin can use the user's keys (§9.5), so:

* content is never rendered as HTML in the app origin. Markdown, notebooks,
  SVG and HTML previews render in a sandboxed iframe on a separate site
  (`hubusercontent.example`), which holds no keys and receives plaintext by
  `postMessage`;
* names and descriptions are escaped, as the CLI already escapes control
  and bidi characters (ARCHITECTURE.md threat model).

### 9.7 Performance for large repositories

* **Lazy trees.** `TreeView` "only loads and decrypts the nodes that are
  actually read" (ARCHITECTURE.md §1), so browsing a directory decrypts that
  directory, not the repository.
* **Prefetch by audience partition**, cached in OPFS: one ranged download per
  pack, verified on read (every object re-hashed against its id). Prefetching
  whole partitions also hides which files the user opens (§3.3).
* **Partial history.** The web client fetches snapshots and trees first and
  blobs on demand. The engine treats a missing object as "redacted"
  (`VeilError::Missing`, ARCHITECTURE.md §2: "Callers treat both as 'exists,
  but not for you'"). Partial clones need a third state, "not fetched yet",
  so that a lazily missing object is never mistaken for a redaction (§10.1).
* **Budgets to measure in phase 0**: WASM size (target ≤ 3 MiB compressed
  without `gix`), AES-SIV and zstd throughput in WASM, time to first file
  view on a 20,000-file repository (the size of the `bench_status` layout,
  ARCHITECTURE.md §6).

---

## 10. MVP and phased roadmap

### 10.1 What must exist in Veil core first

Some of these are cheap now and expensive after the Hub has users. They are
ordered by how much it costs to wait.

| # | Change | Why the Hub needs it | Cost to defer |
|---|---|---|---|
| C1 | **Make "projections are key-independent" an explicit engine invariant**, with a test that computes the public projection and the transfer filter in a repository with no identity and compares | §2.2: every server-side feature rests on it | High: one feature that filters by "which keys this replica holds" breaks the Hub's design |
| C2 | **Extract validation from `remote.rs`** into a transport-independent API (`receive::validate(store, pack, updates, rings, records) -> Report`) used by `pull`, `push` and the server | §4.5: client and server must run the same checks, or the repository splits | Medium; grows with every new check |
| C3 | **Clock injection** instead of `SystemTime::now()` / `Instant::now()` in the engine (`now_millis` in `lib.rs`, `store.rs`, `lock.rs`) | WASM (§9.1), trusted time for embargo deadlines (§8.2), deterministic tests | Low now, grows with every new call site |
| C4 | **A WASM target in CI**: `cargo check --target wasm32-unknown-unknown -p veil-core --no-default-features`, with threads, `DiskBackend`, SFTP and the lock behind features | §9.1 | Medium: unnoticed OS calls accumulate |
| C5 | **Sealed directory nodes** (on the roadmap), designed with the Hub in mind: a sealed directory must still let a keyless relay gc and transfer what is below it (as embargo wrappers list "every object reachable only through the sealed side", ARCHITECTURE.md §7) and must still change id when anything below changes (approval routing, §5.3) | Hides cloaked file names from the Hub, the largest metadata leak (§3.3) | High: names pushed before it are visible forever |
| C6 | **Decide size padding for sealed objects** (a padded plaintext inside `veil:sea2`, or a new sealed tag) | Sizes leak content type and edits (§3.3) | Medium: a format change; old objects stay unpadded |
| C7 | **"Not fetched" distinct from "redacted"** (`Missing` vs a new state) | Partial clones, the web client (§9.7) | Medium |
| C8 | **Embargo record format 2 with escrow recipients** (HPKE wrap bound to the deadline, new signing context) | Embargo modes B and C (§8) | Low: additive, needs a repository format with it |
| C9 | **Reserve the new domain strings** in `crypto/domains.rs`: signature contexts `hub-request`, `hub-identity`, `tag-update`, `review-approval`, `review-comment`, `ring-checkpoint`, `ci-status`; label prefixes `review:`, `ci-log:`, `embargo-escrow:`; KDF context `hub-invite` | All signed Hub statements (§4–§8). CRYPTO.md §3: every domain string lives there, and a test pins them | Low, but cheap now |
| C10 | **Snapshots committing to known ring heads** (a new snapshot field, so a new repository format) | Detect stale writers from history (§6.6) | Medium; design together with C5 and C6 so it is one format bump |
| C11 | **Async or batched object source** for `ObjectStore` (prefetch hints from a walk), or confirm that fetch-then-compute is enough | Web client and partial clone performance | Low |
| C12 | Optional: **co-signed ring changes** (ring format 4) | Client-enforced two-admin rule (§6.7) | None; optional |

C5, C6 and C10 are format changes and should land together in one
repository format (FORMAT.md §4), before the Hub is opened to anyone but the
owner.

### 10.2 Phases

Estimates are engineer-weeks for one experienced Rust engineer, including
tests in the style of the existing suites (adversarial, crash-injection),
and excluding the external security audit that must precede any use with
team production secrets.

| Phase | Contents | Estimate |
|---|---|---|
| **0. Core prerequisites** | C1–C4, C7, C9, C11; WASM proof of concept: open a repository in a browser worker, decrypt a file, measure the §9.7 budgets | 6–9 |
| **1. The Hub as a smart remote** | Accounts (WebAuthn), identity registration, orgs and repository ACLs; the protocol over HTTPS and `vl-serve` over SSH (§4); push validation (§4.5 checks 1–11, 13); audience filtering and partitioned packs; signed tag updates; `hub:` remotes in `vl`; server push log; public renderer | 14–18 |
| **2. Web client, read and administer** | WASM worker, OPFS backend, passkey-wrapped browser identity; history, trees, files, diffs, scopes and ring logs, embargo state; invitations with out-of-band codes (§6.3); grant, revoke, rotate from the browser; offboarding (§6.5); team-to-scope requests; ring checkpoints (§6.6) | 12–16 |
| **3. Pull requests** | PR model on change ids, revisions, touched scopes, sealed comments and anchors, per-scope signed approvals and carry-over, protection rules, client-side merge (CLI and browser), embargoed PRs, pre-publish gate (check 12) | 12–16 |
| **4. CI** | Runner agent, dispatch, runner policy, sealed logs, signed statuses, secrets via a CI scope, hub-hosted runners for the public projection | 8–12 |
| **5. Embargo service and Git mirror** | Deadline worker (mode A), escrow release service (mode B, needs C8), advisories and coordinated disclosure, server-side Git mirror, GitHub PR import | 8–11 |
| **6. Hardening for others** | Reproducible web builds, signed manifests, transparency log, pinning extension, desktop app, native-only scopes, optional governance (§6.7), key transparency for the identity directory, sealed trees (C5) and padding (C6) in production | 14–20 |
| **7. Scale** | Partial clone, sparse fetch, streaming pack building on the server, server-side incremental repacking, time-lock mode C | 8–12 |

Total: roughly 80–115 engineer-weeks. Phases 4 and 5 can run in parallel
with 3; phase 6 must finish before the Hub is opened to anyone outside the
owner's team.

### 10.3 MVP

**Phases 0–3**, about 44–59 engineer-weeks: the smallest product that does
something a team SSH remote plus GitHub cannot.

* A solo developer or small team hosts a mixed repository on the Hub,
  pushes and pulls with `vl` (`hub:` remotes, server-side validation, CAS on
  refs), and keeps their SFTP remote as a mirror if they like.
* Anyone browses the public projection without signing in; members browse
  everything they hold keys for, in the browser, decrypted locally.
* Admins invite teammates with an out-of-band code, grant, revoke and
  rotate from the browser or the CLI, and offboard with a rotation list.
* PRs span open and closed files; each viewer sees their part; approvals are
  per touched scope, signed, verified by the merging client, and carried
  across rebases when a scope's content did not change; merges, including
  embargoed ones, run in the client and are pushed.

Not in the MVP: CI, the release service (embargoes release as today, by
key holders, with Hub notifications), server-side Git mirroring (`vl git
push` from a client, as today), the pinning extension and the desktop app.
Until phase 6, the MVP is for the owner and their team only, with the web
client treated as "as trustworthy as the Hub" and sensitive scopes kept to
`vl`.

---

## 11. Open questions and risks

### 11.1 Open questions

1. **Where do review records live?** In the Hub's DB (simple, like GitHub)
   or as signed objects in the repository (portable, verifiable offline,
   survive leaving the Hub)? The design stores signed statements in the DB
   and exports them; moving them into the repository is a format question.
2. **Org-level scopes.** One ring per repository means one signature per
   repository per change. Should a ring be shareable across repositories
   (an org keychain), and how does that interact with per-repository rings
   that fast-forward independently?
3. **Devices.** One identity per device (more grants, clean revocation) or
   linked devices sharing one identity (fewer grants, revocation means
   replacement)? The design defaults to per-device.
4. **Readable or opaque scope names.** Opaque by default costs readability
   on public remotes and in Git exports' absent paths; readable names leak
   project structure.
5. **Confidential-computing runners** (attested VMs) as hub-hosted runners for
   closed code: do they satisfy "zero knowledge" for this owner, given the
   trust they put in a hardware vendor?
6. **Abuse handling.** A zero-knowledge host cannot scan closed content for
   malware or illegal material. Closed content only in verified orgs, no
   anonymous sharing of closed content, and a report flow in which a member
   decrypts and reports: is that enough for the operator's legal position?
7. **Lawful-access requests.** The Hub can hand over metadata (§3.3) and
   ciphertext only. A transparency report and a canary are cheap; a request
   to serve a modified web client to one user is the case §9.5 cannot fully
   prevent.
8. **Hub-enforced versus client-enforced rules.** Protection rules are
   enforced by the Hub and re-verified by merging clients. Should `vl`
   refuse to *pull* a tag move that the repository's signed policy forbids,
   which would make the rules hold against a compromised Hub too?
9. **GitHub as a second review venue.** Is a one-way flow (GitHub PRs
   imported into the Hub, mixed PRs never mirrored) acceptable to
   outside contributors who live on GitHub?
10. **Pricing of storage.** Ciphertext does not deduplicate across scopes or
    compress, and partitioned packs trade deltas away; storage per user is
    higher than a Git host's.

### 11.2 Top risks

| # | Risk | Likelihood / impact | Mitigation | Residual |
|---|---|---|---|---|
| 1 | **Web-client delivery**: a compromised Hub serves key-stealing code | Medium / critical | §9.5: native-only scopes, separate browser identities, reproducible signed builds, transparency log, pinning extension | Targeted one-time attack on users without the extension |
| 2 | **Identity substitution** in the directory or at invitation | Medium / critical | Out-of-band invite codes (§6.3), fingerprints, binding checks (C4); key transparency in phase 6 | Users who skip verification and accept a Hub-sent link |
| 3 | **Freshness and equivocation**: withheld revocations, rolled-back tags, different views for different users | Medium / high | Ring checkpoints and gossip (§6.6), signed tag updates (§4.6), C10 | A window up to the checkpoint period; fresh clones remain TOFU |
| 4 | **Metadata leakage** larger than users expect: file names, sizes, membership names, access patterns | High / medium | Sealed trees (C5), padding (C6), opaque scope names, partition prefetch; the UI states what the Hub sees | Timing, sizes, who-works-with-whom |
| 5 | **Validation divergence and hostile input at scale**: server and clients disagree on what is valid, or a crafted push exhausts the server | Medium / high | One validation API (C2), the same adversarial and crash suites against the server, limits (§4.8), fuzzing of decoders and ring replay | New checks added to one side only |

Other risks: scope proliferation from per-file sharing (§6.4) making rings
expensive to maintain; the owner's sole-admin scopes with governance off
(§6.7); time-lock (mode C) adding a pairing-based primitive outside the
current crypto review; a team reading "zero-knowledge" as "metadata-private".

### 11.3 For the human security reviewer

The constructions and their limits are in [CRYPTO.md](CRYPTO.md); the
open questions there (§7) still apply. Specific to the Hub:

1. **The keyless-projection invariant** (§2.2, C1). Is there any path,
   today or planned, where what a public remote, Git or a per-viewer
   audience receives depends on keys the sender holds? `Transfer::allowed`,
   `embargo_withheld`, `push_closure` and `git/project.rs` are the places to
   read.
2. **Sealed-object authorship** (§4.5 check 6): accepting new ciphertext
   labelled `S#k` only from members of `S`. Is "member by ring replay at
   generation `k`" the right test, given that the server cannot check that
   the ciphertext opens?
3. **The invitation tag** (§6.3): keyed BLAKE3 (key derived from a 128-bit
   random secret) over `I ‖ 0 ‖ P`. The Hub sees the tag and `P` and can
   search for the secret offline; with a random 128-bit secret that is out
   of reach, but a short spoken code (the 6-word variant) is not, so should
   that variant use a PAKE instead? Is a URL fragment a safe carrier
   (browser history and sync, link previews, screenshots)?
4. **Approval carry-over by object id** (§5.6). It relies on deterministic
   sealing: equal `(path, id)` pairs mean equal content. Is there a way for
   an author to keep an `ops` approval while changing `ops` content (for
   example by changing the base, a fallback, or the policy instead of the
   file)?
5. **Ring checkpoints** (§6.6): does refusing to seal under a ring whose
   checkpoint is older than seven days bound the freshness attack enough,
   and what is the right behaviour when every admin is away?
6. **Browser key storage** (§9.3): passkey PRF as the wrapping key for the
   browser identity; non-extractable WebCrypto keys for signing only. Is
   splitting HPKE's DH step out of the `hpke` crate worth it, or is it the
   kind of homemade composition CRYPTO.md §1 rules out?
7. **Escrow release** (§8.3): HPKE wrap of the embargo key to a release
   service, `aad` bound to the embargo id and deadline. Is the separation
   of the release service from the Hub real enough to claim, and should the
   escrow be split (k-of-n release services)?
8. **Time-lock encryption** (§8.4): acceptable to add drand tlock (BLS12-381
   pairings, IBE) to the reviewed primitive set, and under what conditions?
9. **Request signing** (§4.3): Ed25519 over the origin, path, body hash,
   timestamp and nonce under a new context. Replay window, clock skew and
   session-token binding.
10. **New signing contexts** (C9): seven new contexts and three label
    prefixes. Are any two of the proposed signed bodies ambiguous with each
    other or with existing ones?
11. **Residual web risk** (§9.5): is "native-only for admins and sensitive
    scopes, web identities separate and revocable" an honest enough
    position to ship the web client at all, or should closed content in the
    browser wait for signed web bundles?
12. **Metadata** (§3.3): which items are acceptable for the target users, and
    which must be fixed (C5, C6) before the Hub holds anyone else's code?
