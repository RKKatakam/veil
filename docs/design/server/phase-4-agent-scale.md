# Phase 4: landing at agent scale

> **Owner decisions (2026-11-06):** every recommended default in the README's product-decision list is approved. **Embargoes are permission-based, not encrypted:** an embargoed change is plain text behind the server's checks, and **the server flips it public at the deadline.** The time-lock and release-machine designs below are not needed; the embargo release service becomes a scheduled server job. The hidden embargo line (decision 8) stays.

> **Status: design** (2026-11-06). Base: `integration` @ `3851159`. **S17, the landing service, is built** (2026-11-07, `docs/HUB.md` §13.15): the queue, submit checks, lease and fencing, batches, the fast path, pipelining, the landing check, protected branches (`.veilrules`), `vl land` and `vl push` to a protected branch. Its measurements are in `docs/design/scale/LOAD.md` ("The landing service"). As built, the edit set is not stored (it is read from the objects), and protection is opt-in (decision 9 not applied yet).
> Sources of truth: `docs/OVERVIEW.md` and `docs/VISIBILITY.md` (including "Who can see a PR"); where this document disagrees with them, they win. The server as built is `docs/HUB.md` §13. PRs are `HUB.md` §7, embargoes §8, the web client §10. The roadmap is `docs/design/scion-for-developers.md`, phase 4 (items 5.1–5.8, 6.1–6.7). The measured limits are `docs/design/scale/LOAD.md`.

## 1. Goal

**Thousands of agents land into one project's `main` at 1,000 merges a second**, with no agent waiting on a global lock and no agent ever pulling to catch up. Changes that don't overlap land in batches with one move of `main`; changes that overlap are merged by the server or sent back to an agent to fix. `main` is protected; tests run after landing and before deploy; a change that breaks `main` is found and reverted automatically. PRs and review follow `VISIBILITY.md` exactly. Embargoes release on time without the server holding their keys. CI works through the API. The web client shows code by permission and opens secrets only where the keys are.

The design check:

| Rule | How this phase keeps it |
|---|---|
| Server-centric, always connected | Landing, merging, bisect, revert, review and release run on the server or through it. |
| Code is plain text behind the server's checks | The server merges plain-text code itself; every PR, status, count and notification passes the one access function. |
| Only secret files are encrypted | The server moves secret files by id without opening them; a conflict inside one goes to someone with the key. Key rings stay for secrets only. |
| Admins, groups, managers, folder access, public | PR visibility is "can see every file it touches", computed from the same rules. No new kind of access. |
| No Git, no offline mode, no SFTP | None. |

## 2. Where we start (measured, `LOAD.md`)

| What | Measured | Bound by |
|---|---|---|
| One `main`, 1 agent | 74–87 landings/s (a landing takes 10–12 ms: pull, upload, push) | one agent's round trips |
| One `main`, 50 agents | **bends between 20 and 40 landings/s**; at a 40/s target, 29/s land with 12 collisions each, p99 2.9 s | collisions: an agent's catch-up pull takes longer than the gap between landings |
| One `main`, 4–64 agents, closed loop | 1–3 agents land anything in 15 s | unfair: the last lander holds the tip |
| Across 100 projects | 2,094 landings/s (YugabyteDB, one node: 1,069) | the database's write-ahead log: about 8 commits per landing |
| Anthropic's rate, 30,000 a day | 0.35/s, easy | — |

Phase 2 targets 100 landings/s into one `main` (API commits that the server rebases, no catch-up pull). This phase takes it to 1,000 and beyond.

## 3. What people and agents see

### 3.1 Plain English

* **You land a change; you don't push `main`.** `vl land` sends the change to the server and returns when it is on `main`, usually in a fraction of a second. You don't need to be up to date: the server puts your change on top of the latest `main` if it doesn't overlap anything that landed since your base.
* **If it overlaps,** the server merges the file contents itself when they merge cleanly. If they don't, you (or your agent) get the conflict: the file's three versions and the changes that touched it since your base. Fix it and land again.
* **`main` is protected.** Nobody pushes to it directly. `vl push` of `main` in a project with protection lands your new changes instead, so a one-person project notices nothing.
* **Tests run after landing.** `main@tested` is the newest `main` that passed every required check; deploys use it. When a check fails, the server finds the change that broke it and reverts it, and tells its author.
* **PRs** are visible only to people who can see every file they touch, in every revision. An embargoed PR doesn't exist for anyone outside its groups. Lists, counts, search and notifications follow the same rule.
* **Review by intent and risk.** Each PR shows what it is for and how risky it is. Low-risk changes can land with checks alone; risky ones need a person (the project's rules decide).
* **Embargoes release on time,** even if nobody who holds the key is online, and the server never holds the key before the deadline.
* **The web client** shows the code you may see, PRs and history. Secrets are opened only in a browser that holds a key for them (if the owner allows it at all, §11).

### 3.2 CLI

```text
vl land [REV] [--onto main] [--no-wait]       land a change (default: @'s change onto the default branch)
vl land --status [TICKET]                     queued | landed at main@… | conflict | rejected
vl push                                       to a protected branch: lands the new changes instead

vl pr create [REV…] [--title T] [--body B]    a PR for a stack of changes
vl pr list | show ID | diff ID | checkout ID
vl pr review ID --approve | --request-changes [-m M]
vl pr comment ID [--path P --line N] -m M
vl pr land ID                                 submit an approved PR to the landing service

vl checks -r REV                              statuses on a snapshot
vl tested [BRANCH]                            the newest snapshot that passed every required check
vl bisect --server --check NAME [--from GOOD --to BAD]   server-side bisect (also automatic)

vl embargo create … --until T                 as today (`vl merge … --embargo-for G… --until T`), now through the server
vl embargo release ID                         early release by someone with the right (as today)

vl rules                                      show the protected-branch and review rules
vl stats                                      health metrics (admins)
```

## 4. Architecture

```text
 agents ──► API servers ──► landing queue (DB) ──► landing service (one per protected branch, leased)
   │          submit checks        │                    │ fast path in memory, content merges by merge workers
   │                               │                    ▼
   │                               │              object store  ◄─ new trees and snapshots, written first
   │                               │                    ▼
   │                               └──────────── one transaction: snapshots, landings, queue, CAS of `main`
   │                                                    │
   ◄──────────── events: landed | conflict | check requested | PR updated (filtered per viewer) ◄┘
                                                        │
 CI machines ◄── check requests, diffs, files ──────────┤
 bisect and revert service ◄── failed checks ───────────┤
 release service ◄── embargo deadlines ─────────────────┘
```

### 4.1 Submitting a landing

`vl land` (or `POST …/land`) names a change: a snapshot the client uploaded (as a push does), or an edit list (phase 2's API commit). The API server:

1. resolves the change's **base** (its first parent) and computes its **edit set**: each changed path with the entry at the base and the new entry (the server reads real trees, grafting what the agent cannot see, `HUB.md` §13.4);
2. runs the push checks (`HUB.md` §4.5): write access per path, `.veilpolicy` changes from admins only, object checks, secrets as ciphertext, the server-side secret scan, the agent session's narrower paths;
3. stores the edit set as an object and inserts one row in the **landing queue**; answers `queued` with a ticket.

The client waits on the ticket (a long poll, or its event stream) for `landed`, `conflict` or `rejected`. Submitting is one request and one database commit.

### 4.2 The landing service and batched landings

For each protected branch, exactly one **landing service** runs, on whichever server holds the branch's **lease** (a database row renewed every second, taken over 2 seconds after its holder stops renewing). It loops:

```text
loop:
  batch := every ready entry that arrived while the last batch was being committed (group commit),
           at most 500, in fair order (§4.9), reverts first
  tree  := main's current tree, in memory (decoded trees cached)
  for e in batch:
     if e changes .veilpolicy or the branch rules: end the batch before e; e lands alone, next
     if every path in e's edit set still has, in tree, the entry e's base had there   (the fast path)
        apply e's edits to tree; build snapshot S_e:
           parents [previous snapshot in this batch, or main], change id e.change,
           predecessors [e's submitted snapshot], author, attribution, description,
           signed by the server
     else hand e to the merge workers (§4.3); it leaves this batch
  write the new trees and snapshots to the object store (in parallel; one durability barrier)
  one transaction:
     insert snapshot, landing and audit rows; mark queue entries landed;
     UPDATE branches SET target = last S WHERE project = … AND name = 'main' AND target = old
        AND (SELECT holder, epoch FROM landing_leases …) = (me, my epoch)           -- fencing
  publish "main moved" with the landed tickets
```

* **Batches land change by change.** Each change is its own snapshot, each the first parent of the next, so history, blame, bisect and revert stay per change. A batch of 500 changes is 500 snapshots and **one** move of `main`.
* **The fast path** never merges contents: it checks, for each changed path, that the entry is what the change's base had (and that each folder above it still is a folder), and rewrites only the folder listings on the way from the root to the changed files. A rename is a delete and an add, checked the same way.
* **Agents never catch up.** The base can be minutes old. The check is exact: a change that edited `src/a.rs` from version X lands if `main` still has X at `src/a.rs`, whatever else moved. This removes the collisions that bend one `main` at 20–40/s (`LOAD.md` §3).
* **Pipelined.** While batch `n` is being written and committed, batch `n+1` is prepared on top of batch `n`'s tree. Only the landing service moves `main`, so batch `n`'s compare-and-swap fails only if the lease was lost or an admin forced `main`; then batch `n+1` is discarded and rebuilt from the database's tip.
* **Policy changes land alone,** and every later entry's write access is checked again against the new policy (with the permission cache voided first, as `HUB.md` §9.1 requires).
* **A landing check.** Before the transaction, the service verifies for each new snapshot that its diff against its first parent is exactly its edit set (cheap: the paths are known). A mismatch aborts the batch and is a bug report, never a landing.

### 4.3 Overlapping changes: content merges, and conflicts back to agents

* **Merge workers** take an entry whose paths changed on `main` since its base. For each such file, if it is plain text, they run the engine's three-way merge (`merge.rs`, the same rules as the client) of the base's version, `main`'s current version and the change's. If every file merges cleanly, the entry's edit set is rewritten against `main`'s current versions and goes back to the head of the queue; the fast path then re-checks it, so a file that moved again in between is merged again (at most 3 times, then a conflict).
* **A conflict goes back** to the change's author, on their event stream and ticket:

  ```text
  conflict {change, base, onto: "<projected main>",
            paths: [{path, base: <id>, main: <id>, yours: <id>}],
            landed_since: [projected ids of the changes that touched these paths since base],
            checks: [...]}                                     // test results, when known
  ```

  Every path in it is one the change itself touched, so its author may read it; the versions on `main` are at the same paths. The changes listed are projected for the author, with descriptions per `HUB.md` §13.4. The agent fetches the three versions (phase 2), resolves, and lands again (a new revision of the same change id).
* **Changes that need keys** (`scion-for-developers.md` 5.8): a secret file changed on both sides cannot be merged by the server, which holds ciphertext only. It is a conflict for the author, who holds the key (they changed the secret). Secret files that don't overlap take the fast path: the server moves their entries by id without opening them.
* **Semantic conflicts** (two changes that are fine alone and break together) are not detected before landing; tests after landing find them (§4.5).

### 4.4 How 1,000 merges a second into one `main` is possible

| Cost | Today (per landing) | With batched landing |
|---|---|---|
| Moves of the hot row | 1 per landing, plus every collision | 1 per batch |
| Collisions | 0.6–27 per landing above 20/s | none: the server rebases; agents never race |
| Client requests | pull + upload + push, again per collision | upload + `land` |
| Database commits | about 8 | 1 for the submit, plus 1/batch for the landing |
| Server CPU | 4.5–134 ms | about 0.3 ms in the landing service (tree edits in memory, sign, hash), plus the submit's checks on any API server |

At 1,000 landings a second, with a group commit of about 20 ms (PostgreSQL) to 40 ms (YugabyteDB):

* each batch holds 20–40 changes, and `main` moves 25–50 times a second, under the 74–87 moves a second one row sustained in `LOAD.md` §3;
* the landing service spends about 0.3 s of one core per second; the object store receives about 6,000 small writes a second (the trees on each change's path and its snapshot), spread over hash-named keys;
* the database commits about 1,050 times a second for landings, against a WAL ceiling of about 16,000 commits a second implied by `LOAD.md` §2 (2,094 landings a second × about 8 commits each);
* **latency** from `land` to `landed`: one batch wait plus one batch commit, about 50–100 ms at p50.

The same arithmetic gives headroom to about 5,000 a second on one landing service before its one core is the limit; past that, batch size grows and latency with it, still without collisions.

### 4.5 Projected history at 1,000 landings a second

Every viewer without full view needs projected snapshots (`HUB.md` §13.4), and each projection's parents are projections, so a viewer's tip needs every snapshot since their last one projected. Writing a memo row per snapshot per view key would be 1,000 rows a second per active view key.

* **Memo rows only at batch tips, for every view key, eagerly.** Right after each batch, the derive workers project its snapshots for each view key of the project's people (tree projection, where only folders holding a rule are rewritten; encoding; hashing; the server's Ed25519 signature: about 50 µs each) and write one memo row per view key at the batch's tip. The projection of an intermediate snapshot is recomputed in memory from the previous batch tip's memo when asked. So a tip request is never more than one batch of work, however long the viewer was away.
* **A snapshot that changed nothing a viewer sees is free:** `P(S) = P(parent)`, decided from the changed-paths object and the viewer's rules (phase 3) without touching trees.
* **Viewers who see everything** (admins, and anyone whose rules cover every line) get real snapshots and need nothing.
* **Narrowed agent sessions add no view keys.** Narrowing (`--only`) applies to files: trees, grants, reads and writes. A session's history is its person's projection. So the number of view keys is the number of distinct read sets among the project's people, usually tens, not the number of agents.
* Cost: at most 50 ms of CPU a second per view key at 1,000 landings a second; with 20 view keys, one core.

### 4.6 Protected `main`

* A branch rule `protected = true` refuses every push that moves the branch, except an admin's `vl push --force` (recorded in the audit log and shown in `vl stats`). Only the landing service moves it.
* **`vl push` to a protected branch lands instead:** the new changes between the server's tip and the pushed one are submitted to the landing service in order, as one stack, and `vl push` waits for them.
* Release branches can be protected too; each protected branch has its own landing service.

### 4.7 Land first, test after; automatic bisect and revert

* **Checks run on landed snapshots.** A CI machine (§4.10) tests the newest tip of `main` whenever it finishes its previous run, so it skips tips when `main` moves faster than tests run. Results are statuses on snapshots.
* **`main@tested`** is a server-side pointer: the newest snapshot of `main` on which every required check passed. It only moves forward. Deploys read it (`vl tested`, `GET …/tested/main`).
* **A failure starts a bisect** between the last tip that passed and the first that failed:
  * **narrowed by paths:** if the failing check declares the paths it depends on (`paths = ["src/api/", "Cargo.lock"]` in the rules), only changes that touched them are candidates (phase 3's file history); usually a handful among thousands;
  * **k-ary:** the bisect service asks for up to `k` checks at once (the project's CI capacity, default 8), dividing the range by `k + 1` each round;
  * **confirmed:** the culprit must fail and its parent pass, each run twice, so a flaky test never reverts anyone.
* **Automatic revert:** the service creates a change that reverses the culprit's edits, and lands it through the priority lane of the landing service. If later changes touched the same lines, the revert is a conflict like any other, and goes to the culprit's author with the failing check's output, as the "fix forward" request. Either way the author is told: `reverted: your change C broke ci/test-api (log: …)`.
* **Embargoes never meet this:** an embargoed fix reaches `main` only at its release (§4.8), as plain text, so a revert never reveals it early. This answers `HUB.md` §12.1, question 5.
* Whether the revert lands without asking anyone is a product decision (§11, item 4).

### 4.8 Embargoes through the server, and the release service

**What changes.** Today's engine keeps an embargoed merge on `main` and makes everything on top of it hidden for outsiders until release ("sticky", `ARCHITECTURE.md` §7, "Trade-offs"): outsiders cannot even record on top of it. On a `main` that thousands of agents land into, that would stop them all until the release. So:

* **Until release, the fix lives on a hidden embargo line,** `embargo/<id>`: `main` as it was at the merge, plus the fix, as plain text behind the server's checks. Only the embargo's groups (and admins, who see everything) know the line exists; for everyone else it has no name, no count and no placeholder. Its groups get the fix right away: code, message and history.
* **`main` keeps moving for everyone.** A member of the embargo's groups (or a machine in them) may rebase the line onto newer `main` (`vl embargo follow ID`), as plain landings never touch it.
* **At release,** the content becomes ordinary plain text (as `HUB.md` §8.3 says), and the server lands the fix onto `main` through the landing service like any change. A conflict goes back to the embargo's authors.
* This is a product decision for the owner (§11, item 1).

**Releasing on time.** The key-holder, release-machine and time-lock designs of this round are not needed (the owner's decision at the top): embargoes are not encrypted (repository format 8), and the server makes the fix public at the deadline as a scheduled job.

**Embargoed PRs** exist only for the embargo's groups: their visibility class includes the embargo (§4.9), and they appear in no list, count, search or notification of anyone else.

### 4.9 PRs and review

**Who can see a PR** (`VISIBILITY.md`, exactly):

* A PR is visible only to people who can see **every file it touches**. "Touches" is the union over **all its revisions**, because earlier revisions' diffs and comments stay part of it: a PR that once touched `billing/` stays hidden from those who cannot see `billing/`.
* **An embargoed PR doesn't exist** for anyone outside its groups.
* **The same check everywhere:** lists, counts, search, notifications, the API, agents, CI, the event stream.

**How, without per-viewer work.** Each PR has a **visibility class**: the set of access lines deciding its touched paths, plus its embargo if any. A viewer sees the PR if the class's lines are all in their rules `R(v)` (admins: all) and they are in the embargo's groups. Classes are few (they are sets of lines); for each request the server computes the classes the viewer satisfies, once per view key, and lists, counts and searches **only PRs in those classes** (an index on `(project, class)`). The work and the answer depend only on what the viewer may see.

**PR names.** Sequential numbers would leak hidden PRs through gaps (#12, #14: #13 is hidden). PRs are named by short random ids (`pr-4f2a9c`), like change ids. This is a product decision (§11, item 3).

**Notifications** are checked against the current visibility at delivery, not when queued. A PR that becomes invisible to someone (a new revision touched a folder they can't see) stops notifying them; they keep what they already received.

**Review by intent and risk.**

* **Intent:** the PR's description and the agent's task (phase 2 attribution) say what it is for; the PR page groups its diff by change in the stack.
* **Risk:** the server classifies each revision:

  | Risk | When |
  |---|---|
  | **low** | only documentation, comments, whitespace or tests (by path rules, and by a comment-only check for languages the server parses) |
  | **normal** | anything else |
  | **high** | touches `.veilpolicy` or the rules, CI configuration, dependency manifests and lock files, secret files, or paths the admins mark high-risk (`src/auth/`); or is very large |

* **The rules** say what each risk needs (for example: low lands with checks alone; normal needs one approval; high needs one approval from a person, not an agent). Which defaults ship, and whether agents' approvals count, are product decisions (§11, item 5).
* **Approvals** are recorded per revision with the reviewer's device signature and dismissed when the files change (`HUB.md` §7.4). A reviewer can approve only what they can see, which for a PR is everything it touches.
* **Landing a PR:** when its rules are met, `vl pr land` (or the rules' auto-land) submits its stack to the landing service.

**Where the rules live.** A tracked `.veilrules` file at the project root, accepted like `.veilpolicy`: only an admin's push to the default branch changes it. (Product decision §11, item 7.)

```toml
[branches.main]
protected = true
required_checks = ["ci/build", "ci/test"]
[review]
low = { approvals = 0 }
normal = { approvals = 1 }
high = { approvals = 1, people_only = true }
high_risk_paths = ["src/auth/", "infra/"]
[checks."ci/test-api"]
paths = ["src/api/", "Cargo.lock"]
```

### 4.10 CI through the API

* **A CI machine is added like a person** with the groups it needs (`VISIBILITY.md`). Each job runs with an **agent session narrowed to the paths it declares** (phase 2), so what a job could read is enforced, not claimed.
* **Work comes as events:** `GET …/events?types=main.moved,pr.revision,check.requested` (server-sent events), filtered per viewer like everything else.
* **A job needs no clone:** the diff against the merge base and the files it needs come from the query API (phase 3) and a thin workspace (phase 2), in seconds.
* **Statuses:** `POST …/checks {snapshot, name, state, summary, url}`. **A status is shown to someone only if they can see every path the job's session could read** (and the snapshot), so CI output about `billing/` never reaches someone who can't see `billing/`.
* **The bisect service** asks for checks at chosen snapshots with `check.requested` events.

### 4.11 Health metrics, rate limiting, failure isolation

**Health metrics** per project and protected branch: landings per second and per day, time to land (p50, p99), batch size, queue depth, conflict rate, content merges, reverts, time from landing to `main@tested`, cache hit rate per layer, derive lag (phase 3), rate-limit refusals. **Admins only** (`vl stats`, `GET …/health`), because the counts include work others may not see.

**Rate limits** (token buckets, kept in each API server's memory, so no database work per request):

| Limit | Default |
|---|---|
| requests per device, per agent session | 60/s burst, 5,000/h (`HUB.md` §4.7) |
| outstanding landings per agent session | 100 |
| landing share per person in a batch | fair: round-robin over people, then over each person's sessions |
| anonymous reads of public folders, per IP | lower |

A runaway agent fills only its own queue; the batch takes it in turn with everyone else.

**Failure isolation:**

* each protected branch's landing service is separate: a crash stops that branch for at most 2 seconds (the lease);
* per-project limits on concurrent requests in every API server, so one project's storm cannot starve another;
* caches, derive workers, search, CI events and the release service run apart from landing; **landing never waits for any of them**;
* under overload, the server sheds in this order: search and grep, derive work (lag grows), pulls (`busy` with `retry_after_ms`), and landings last.

### 4.12 The web client

* **TypeScript UI** over the same JSON API as `vl`, with **`veil-core` compiled to WASM** for decoding objects, verifying snapshot signatures and grants, and diffs.
* **Code is plain text served by permission:** every page is a query of phase 3 with the viewer's session, projected the same way. Anyone on Earth sees `public` folders, including server-rendered pages for search engines.
* **Sign-in with a passkey;** the session cookie is `HttpOnly`, `Secure`, `SameSite=Strict` (`HUB.md` §4.3).
* **Repository content is hostile:** rendered Markdown, notebooks and HTML are shown from a separate, sandboxed origin with no session; the app uses a strict CSP and Trusted Types.
* **Secrets in the browser,** only if the owner allows it (§11, item 6): a browser device identity made in WASM in a Web Worker, its private keys stored encrypted under a key derived from the passkey (WebAuthn's PRF extension), **confirmed like any device** (fingerprint or a vouch from the person's other device, `HUB.md` §13.11) before any secret key is wrapped to it. The secret is decrypted in the Worker and shown only when asked.
* **The limit to be honest about:** the web client's code comes from the server. A server that was broken into could serve code that sends decrypted secrets back to itself. That breaks "the server never sees secrets" for anyone who opens a secret in the browser. The first version therefore shows secrets as "open with `vl`" (§11, item 6).

## 5. Data model and protocol changes

### 5.1 API

| Route | |
|---|---|
| `POST …/land {change | snapshot | edits, onto}` → `{ticket}` | submit (§4.1) |
| `GET …/land/{ticket}` | long poll: `queued`, `landed {snapshot, position}`, `conflict {…}`, `rejected {code}` |
| `GET …/events?types=` | server-sent events, per viewer: `main.moved`, `landed`, `conflict`, `pr.*`, `check.requested`, `reverted`, `embargo.released` |
| `POST …/checks`, `GET …/checks?rev=` | statuses |
| `GET …/tested/{branch}` | `main@tested` |
| `POST …/bisect {check, good, bad}` | a bisect by hand (automatic ones start on failures) |
| `POST …/prs`, `GET …/prs?state=`, `GET …/prs/{id}`, `…/revisions`, `…/threads`, `…/reviews`, `…/land` | PRs (`HUB.md` §7.2–7.5) |
| `POST …/embargoes/{id}/release` | a release by someone with the right |
| `GET …/health` | metrics (admins) |

### 5.2 Database

```sql
CREATE TABLE IF NOT EXISTS landing_queue (
    project_id BIGINT NOT NULL,
    branch TEXT NOT NULL,
    seq BIGSERIAL,
    ticket TEXT NOT NULL UNIQUE,
    change_id TEXT NOT NULL,
    submitted TEXT NOT NULL,               -- the submitted snapshot (or the API commit's)
    base TEXT NOT NULL,
    edits TEXT NOT NULL,                   -- object id of the edit set
    person_id BIGINT NOT NULL,
    session TEXT NOT NULL,                 -- the agent session's hash, for fair share and limits
    priority INT NOT NULL,                 -- 0 normal, 1 revert
    state TEXT NOT NULL,                   -- ready | merging | landed | conflict | rejected
    result TEXT,                           -- JSON: landed snapshot, or the conflict
    created_at BIGINT NOT NULL,
    PRIMARY KEY (project_id, branch, seq)
);
CREATE TABLE IF NOT EXISTS landing_leases (
    project_id BIGINT NOT NULL,
    branch TEXT NOT NULL,
    holder TEXT NOT NULL,                  -- server instance
    epoch BIGINT NOT NULL,                 -- fencing token: bumped on every takeover
    expires_at BIGINT NOT NULL,
    PRIMARY KEY (project_id, branch)
);
CREATE TABLE IF NOT EXISTS landings (
    project_id BIGINT NOT NULL,
    landed TEXT NOT NULL,                  -- the snapshot on main
    submitted TEXT NOT NULL,
    batch BIGINT NOT NULL,
    PRIMARY KEY (project_id, landed)
);
CREATE TABLE IF NOT EXISTS checks (
    project_id BIGINT NOT NULL,
    snapshot TEXT NOT NULL,
    name TEXT NOT NULL,
    state TEXT NOT NULL,                   -- pending | pass | fail | error
    summary TEXT, url TEXT,
    session_paths TEXT NOT NULL,           -- what the job could read: decides who sees the status
    by_person BIGINT NOT NULL,
    at BIGINT NOT NULL,
    PRIMARY KEY (project_id, snapshot, name)
);
CREATE TABLE IF NOT EXISTS tested (
    project_id BIGINT NOT NULL, branch TEXT NOT NULL, snapshot TEXT NOT NULL,
    PRIMARY KEY (project_id, branch)
);
-- PRs (HUB.md §7.2), with visibility classes (§4.9).
CREATE TABLE IF NOT EXISTS pr_classes (
    project_id BIGINT NOT NULL,
    class_id BIGSERIAL,
    lines TEXT NOT NULL,                   -- sorted JSON list of line keys
    embargo TEXT,                          -- embargo id, or NULL
    PRIMARY KEY (project_id, class_id),
    UNIQUE (project_id, lines, embargo)
);
CREATE TABLE IF NOT EXISTS prs (
    project_id BIGINT NOT NULL,
    id TEXT NOT NULL,                      -- short random id
    class_id BIGINT NOT NULL,
    target TEXT NOT NULL,
    author BIGINT NOT NULL,
    title TEXT NOT NULL, body TEXT NOT NULL,  -- ciphertext for an embargoed PR
    risk TEXT NOT NULL,
    state TEXT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (project_id, id)
);
CREATE INDEX IF NOT EXISTS prs_by_class ON prs (project_id, class_id, state, updated_at);
-- pr_revisions, pr_threads, pr_comments, pr_reviews: as HUB.md §7.2–7.4.
CREATE TABLE IF NOT EXISTS embargo_lines (
    project_id BIGINT NOT NULL,
    embargo_id TEXT NOT NULL,
    branch TEXT NOT NULL,                  -- embargo/<id>: hidden from everyone outside its groups
    groups TEXT NOT NULL,
    deadline BIGINT,
    released_at BIGINT,
    PRIMARY KEY (project_id, embargo_id)
);
```

`branches` gains a `hidden_for_embargo` column so `tips`, `history` and every listing leave out embargo lines for everyone outside their groups (S1 shows branch names to all participants, `HUB.md` §13.8).

### 5.3 Object store

New objects: edit sets, and the trees and snapshots the landing service builds. No change to existing objects. (The time-lock's new embargo record version is not needed: embargo records are plain since repository format 8.)

## 6. Threat review

| # | Attacker | Capability | Harm | Mitigation | Test |
|---|---|---|---|---|---|
| 1 | An agent with access to `src/` only | submits an edit set touching `billing/` | writes where it may not | write access checked at submit, and again in the batch against the current policy | `landing_access`: edits outside the session's paths, and outside the person's, are rejected at submit and, after a policy change in between, at the batch |
| 2 | An admin and an agent at once | a policy change and changes relying on the old policy in one batch | a change lands under rules that no longer allow it | policy and rules changes land alone; later entries re-checked; permission cache voided first | a revoking policy change queued between two writes of the revoked path: the second is rejected |
| 3 | — (failover) | two servers both believe they run the landing service | `main` moved twice from one tip, or a lost change | the lease's epoch is checked in the compare-and-swap transaction (fencing) | kill and pause the leaseholder in a loop under load: every ticket ends `landed` exactly once or `rejected`, and each landed snapshot is on `main` |
| 4 | — (a bug) | the fast path rewrites a tree wrongly | a change lost or altered on `main` | the landing check (each new snapshot's diff equals its edit set) before the transaction; property test against sequential rebases | random non-overlapping and overlapping edit sets: `main` after batching equals applying them one by one with the engine's rebase |
| 5 | The author of a conflicting change | reads the conflict report | learns about hidden folders or changes | the report holds only paths the change touched (readable by its author) and projected changes | conflicts between a full-view agent and a narrowed one: the narrowed one's report names nothing it cannot read (projection equivalence of phase 3, applied to conflicts) |
| 6 | Someone who breaks into the server | asks the merge workers to merge a secret | reads a secret | secrets are ciphertext; the server never has the key; overlapping secrets are conflicts for the author | a secret changed on both sides: conflict, and no plaintext anywhere on the server |
| 7 | Person without access to `billing/` | lists, counts, searches PRs; reads notifications; watches the event stream; times listings | learns a hidden PR exists, or its title | visibility classes; work only on satisfied classes; random ids; notifications re-checked at delivery | projection equivalence for PR routes and events: answers equal those on a project built from the viewer's view; no id gaps exist to count |
| 8 | Person outside an embargo's groups | lists branches, PRs, events; searches | learns an embargo exists before release | hidden embargo lines; embargoed PRs in a class with the embargo; nothing indexed | an embargoed fix with its PR: outsiders' every answer equals the same project without it, until release |
| 9 | Anyone | watches `main` for a revert of an embargoed fix | learns the fix early | embargoed fixes reach `main` only at release | an embargoed change whose release fails a check: the revert happens after release, never before |
| 10 | A CI job with broad access | posts a status about `billing/` on a public snapshot | leaks hidden test output | a status is shown only to people who can see every path the job's session could read | a job session with `billing/` posts on a public change: invisible to public viewers; a job narrowed to `src/` is visible to them |
| 11 | Someone who breaks into the server | releases an embargo early | publishes the fix before the deadline | not mitigated by encryption: embargoes are permissions the server enforces (the owner's decision at the top) | |
| 12 | Same | delays or suppresses a release | the fix stays hidden too long | accepted (availability is the server's); someone with the right can release by themselves | |
| 13 | A runaway agent | submits 10⁵ landings, or opens 10⁴ sessions | starves other agents | per-session outstanding cap; fair share per person, then per session; per-person request limits across sessions | one agent floods while 1,000 others land at 1/s: the others' p99 stays within its target |
| 14 | — (flaky test) | a check fails at random | the bisect reverts an innocent change | the culprit must fail and its parent pass, twice each | a 5 % flaky check over 1,000 landings: no automatic revert |
| 15 | A reviewer | approves revision 2 then the author pushes revision 3 | an unreviewed change lands | approvals bound to a revision, dismissed on any file change, device-signed | approve, push, land: refused until approved again |
| 16 | An agent | approves its own person's risky PR | the human check is skipped | rules can require people's approvals for high risk; an approval from a session of the PR's author never counts | an agent session of the author approves: not counted |
| 17 | Hostile repository content | Markdown or HTML with scripts in the web client | steals a session | separate sandboxed origin with no session; CSP; Trusted Types | an XSS corpus rendered: no script runs on the app's origin |
| 18 | Someone who breaks into the server | serves modified web client code | reads secrets opened in a browser | the first version opens no secrets in the browser (§4.12, §11 item 6) | the web client has no code path that decrypts a secret while the option is off |
| 19 | An admin | forces `main` | bypasses review | allowed (an admin's deliberate command), audited and shown in `vl stats` | a forced move appears in the audit log and the metrics |
| 20 | Anyone | many anonymous reads of public folders | exhausts the server | lower per-IP limits; public objects served by caches and CDNs | the load test with an anonymous flood: signed-in pulls keep their targets |

## 7. Performance targets and the benchmark

**How this phase moves the owner's numbers:**

| Number | After phase 2 (target) | After phase 4 (target) |
|---|---|---|
| Landings/s into one `main` | 100 | **1,000 sustained**, headroom to about 5,000 |
| Landings/s across projects (one machine) | 4,000 | **10,000** (about 1 commit per landing); more with YugabyteDB nodes |
| Pulls/s while `main` moves 1,000/s | 1,000+ | **1,000+**, unchanged by the landing rate (thin pulls, batch-tip memos) |
| Merges per day, one project | about 8 million capacity | **about 86 million capacity**; 1 million a day is 1.2 % of it, so 10× peaks fit |
| Agents landing into one `main` | collisions above 20–40/s | **10,000**, none waiting on another |
| Time to land, p50 / p99 | — | **under 150 ms / under 1 s** at 1,000/s |
| PR open or update | — | **under 100 ms** server time |

**The benchmark:** `veil-bench load --mode land --landing-service` (extended):

* one project, one protected `main`, **10,000 agents**, open loop at **1,000 landings/s for 10 minutes**; 95 % of changes don't overlap, 3 % overlap and merge cleanly, 2 % conflict;
* at the same time, **1,000 thin pulls/s** and phase 3 queries;
* measured: landed per second; submit-to-landed p50 and p99; batch sizes; database commits and statements per landing; server CPU per landing; fairness (every agent lands, and the least served agent lands at least half the mean); conflicts delivered;
* gates: 1,000/s sustained, p50 under 150 ms, p99 under 1 s, at most 1.5 database commits per landing, every agent served;
* also: `veil-bench prs` (100,000 PRs in 50 visibility classes; list, count and search for a restricted viewer under 50 ms; open and update under 100 ms); `veil-bench bisect` (a culprit among 10,000 landings, found in at most 4 rounds with 8 parallel checks); a failover run (the leaseholder killed every 30 s: no ticket lost, at most 2 s of stall);
* on the development machine with PostgreSQL first, then on the gate hardware with a three-node YugabyteDB cluster (§11, item 8).

## 8. Milestones

| # | Milestone | Contents | Depends on | Touches |
|---|---|---|---|---|
| **S17** | The landing service | queue, submit checks, lease and fencing, group-commit batches, the fast path, pipelining, the landing check, protected branches, `vl land`, `vl push` to a protected branch, tickets and `landed` events (batch-tip projection memos come from S12's derive workers) | S4, S10, S12 | new `veil-server` `landing/`; `crates/vl` |
| **S18** | Content merges and conflicts back to agents | merge workers, re-queue, conflict reports, the event stream (`GET …/events`) | S17 | `landing/merge.rs`, new `events.rs` |
| **S19** | CI through the API; land first, test after | checks and their visibility, CI job sessions, `check.requested`, `main@tested`, `vl checks`, `vl tested`, `.veilrules` `[branches]` and `[checks]` | S11, S13, S17 | new `veil-server` `checks.rs` |
| **S20** | Automatic bisect and revert | path-narrowed k-ary bisect, confirmation runs, revert changes in the priority lane, notifications | S14, S19 | new `bisect.rs` |
| **S21** | PRs and review | PR records, visibility classes, random ids, revisions on change ids, threads and anchors (`HUB.md` §7.3), approvals, risk classification, `.veilrules` `[review]`, notifications, PR search, `vl pr` | S13 (S17 to land) | new `veil-server` `prs/`; `crates/vl` |
| **S22** | Embargoes through the server, and the release service | embargo records accepted by push, hidden embargo lines, `vl embargo follow`, the scheduled release job, landing at release | S2, S17 | `veil-server` `sync.rs`, new `embargo.rs`; `veil-core` `embargo.rs` |
| **S23** | Embargoed PRs | the embargo in visibility classes | S21, S22 | `prs/` |
| **S24** | Rate limits, health metrics, failure isolation | token buckets, fair share, per-project bulkheads, load shedding, `vl stats` | S17 | `veil-server` middleware |
| **S25** | Web client, first version | browse code and history, PRs and review, administration; no secrets | S13, S21 | new `web/` (TypeScript), `veil-core` WASM build |
| **S26** | Secrets in the browser | browser device identity, passkey-protected keys, confirmation, decryption in a Worker | S25, S2; only if the owner approves (§11, item 6) | `web/` |
| **G4** | Phase 4 gate | the benchmarks of §7, on the development machine and the gate hardware | S17–S24 | `crates/veil-bench` |

## 9. Open technical questions

1. **Group commit on YugabyteDB:** a distributed transaction's commit is slower than PostgreSQL's; batches grow to keep 1,000/s, and latency with them. Measure on three nodes; if needed, keep the queue rows in a table co-located with the branch row (same tablet) so the batch transaction stays single-shard.
2. **Object writes per batch:** about 6 small objects per landing. On S3 this is many PUTs; a batch could write its new trees and snapshots as one pack object with an index, if the object store's request rate becomes the limit. Measure first.
3. **Projects with many view keys:** eager batch-tip memos cost about 50 ms of CPU a second per view key at 1,000 landings a second (§4.5). A project whose people have hundreds of distinct read sets needs several cores for it. Compute memos only for view keys used in the last day, and pay one catch-up walk for a returning viewer? Measure how many view keys real projects have.
4. **Comment-only detection** for the low risk tier needs a parser per language; which languages first, and what counts as "comment-only" for generated files.
5. **The time-lock implementation:** not needed (the owner's decision at the top: embargoes are permissions, not encryption).
6. **Hidden embargo lines and `.veilpolicy`:** a fix that changes `.veilpolicy` under embargo would change access at release; refuse policy changes on embargo lines?
7. **Release branches** with their own landing service: how a fix landed on `main` is carried to them (cherry-pick through the landing service, or by hand).

## 10. What this phase does not do

* Run models. Conflicts and failed checks go back to the author's agent; Veil does not choose or run an agent.
* Merge across secrets or unreleased embargoes on the server (no keys there, by design).
* Test before landing. Agents may run tests in their sandboxes before `vl land`; the server does not wait for them.

## 11. Product decisions for the owner

1. **Embargoed merges into a busy `main`.** Today an embargoed merge on `main` hides everything landed on top of it from outsiders until release, and outsiders cannot record on top of it. With thousands of agents that freezes `main`. Recommendation: the fix lives on a hidden embargo line (its groups get it at once) and lands on `main` at release.
2. **On-time release without the server holding keys.** Recommendation: offer the time-lock (drand, an external public beacon run by a group of independent organisations) as the default for embargoes with a deadline, with a release machine as the alternative for teams that don't want an outside dependency. Without either, a release waits for a key holder to be online. *Owner, 2026-11-06: not needed; the server releases at the deadline (the decision at the top).*
3. **PR names:** short random ids (`pr-4f2a9c`) instead of sequential numbers, so hidden PRs leave no gaps. Recommendation: yes.
4. **Automatic revert:** the server reverts a confirmed culprit without asking anyone, and tells its author. Recommendation: yes for protected `main` (land first, test after needs it); a project setting can make it a proposal instead.
5. **What needs a person's approval.** Recommendation for the defaults: low risk lands with checks alone; normal needs one approval (an agent's counts, if it is not a session of the author); high needs one person's approval. Agents' approvals never count for high risk.
6. **Secrets in the browser.** The web client's code comes from the server, so a server that was broken into could read secrets opened in a browser. Recommendation: the first web client shows secrets as "open with `vl`"; later, only through a separately installed, signed extension or app whose code does not come from the server.
7. **Where review and branch rules live:** a tracked `.veilrules` file, changed only by admins, like access lines in `.veilpolicy`. Recommendation: yes; the alternative is server settings with no history.
8. **Gate hardware:** the 10,000-agent, 1,000 landings/s gate needs several machines and a three-node YugabyteDB cluster (paid cloud). Needs approval before anything is rented.
9. **Protected `main` by default** for new projects, with `vl push` landing instead. Recommendation: yes.
10. **Health metrics for admins only,** because counts include work others can't see. Recommendation: yes; per-viewer filtered metrics are possible later.
