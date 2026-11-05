# Veil Hub: design

Status: **design draft, post-1.0.** Nothing here is implemented. Veil 1.0
ships without a server: code goes to a path or SSH remote (team or public)
that needs nothing but SFTP
([ARCHITECTURE.md §1, §8](ARCHITECTURE.md#8-synchronisation)). Veil does not
interoperate with Git, so the Hub has no Git mirror or Git import. This document
designs the hosted service that comes after: a GitHub-like product for
repositories that are partly open and partly closed, in which **the server
never holds a key that opens closed content**.

Every statement about how Veil behaves today cites the document or source
file it comes from. Everything else is a proposal, and is worded as one.

Contents:

1. [Goals, non-goals and personas](#1-goals-non-goals-and-personas)
   * D. [Product and experience design](#d-product-and-experience-design):
     principles, information architecture, the visibility lens, key screens,
     review model, trust UX, visual language, CLI parity, MVP UI
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
  embargoes and the Hub's push log. Its product and experience design is
  [§D](#d-product-and-experience-design).
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
* **Reusing Git's wire protocol.** The protocol is Veil's own (§4), built on
  Veil packs and Veil's sync rules.

### 1.3 Personas

| Persona | Today (1.0) | What they want from the Hub |
|---|---|---|
| **Solo developer** (the owner, first user) | One repository: public code pushed to a public remote, closed code pushed to an SSH remote | One place to see all of it from any machine, a phone included; backups; CI for both halves; no server to run |
| **Small team with mixed open and closed code** (the owner's team) | A team SSH remote, scopes granted by hand with pasted `veil1…` keys, no shared review | Review of *whole* changes, closed parts included; invitations without pasting keys; offboarding that lists what to rotate; per-scope approvals |
| **Open-source maintainer with outside contributors** | A public remote for public code, contributions by hand; the closed parts (deploy configs, release keys, internal docs) are invisible to contributors | Contributors open PRs against the public projection; maintainers review and merge them without exposing closed files; mixed PRs from insiders in the same queue |
| **Security team using embargoes** | `vl merge --embargo --until`, release by hand or by the next key holder's `vl` | Reports from outside researchers, private advisories, a release that happens on time, coordinated disclosure with downstreams, a fix that lands on the public remote the moment it is public |

---

## D. Product and experience design

This section designs what the Hub looks like and how it feels to use. The
rest of this document designs what it does. The section sits right after the
goals because every later section has a face here. It is labelled **D**
rather than numbered, so the numbers of §2–§11 (and the links into them
from other documents) stay as they are.

The owner's requirement is that the Hub must not be a GitHub clone with a
new logo. The repo / branch / commit / pull-request page set fits Git's
model. Veil's model is different, so the product is built from Veil's own
nouns instead.

**Provenance.** Each feature below is one of three kinds:

* behaviour Veil has **today**, cited to the guide or ARCHITECTURE.md;
* behaviour designed in **another section of this document**, cited by §;
* a proposal **new in this section**, marked *(UX addition)*.

A *(UX addition)* that needs server or engine work says so.

Wireframes use these text chips. The real UI pairs each one with an icon
and a pattern (§D.7):

```text
[public]        public file, plaintext                    [public!]  public, secret scanning off
[team]          cloaked for `team`, decrypted on THIS device (you are a member)
[ops: locked]   cloaked for `ops`, you hold no key        [embargo 7793]  under an unreleased embargo
[withheld]      history the Hub will not serve you yet    [device]   isolated: exists only on devices
✓ ✓bob ? ✗ –    signature: good, good (other signer), unknown key, bad, unsigned (as in `vl log`)
@ ○ × ◆         working copy, snapshot, conflicted snapshot, root (as in `vl log`)
```

### D.1 Design principles

Each principle says what GitHub does, what the Hub does instead, and why
Veil's model calls for it.

1. **The change is the unit.** GitHub's unit is the commit, which is
   immutable and dies on every rebase. Veil's unit is the **change**, whose
   id survives describe, rebase and squash
   ([getting-started](guide/getting-started.md#change-ids-and-snapshot-ids),
   ARCHITECTURE.md §5). So every Hub page about history is keyed on a change
   id: URLs, review threads, sign-offs and notifications. Snapshot ids
   appear only where one exact version is meant, as in the CLI.
2. **Time first, tree second.** GitHub opens on a file tree and a README.
   In Veil every command records the working copy as a snapshot, every
   action is an operation, and the work is the evolving graph
   ([getting-started](guide/getting-started.md#no-staging-every-command-snapshots)).
   So a member's repository home is a **timeline** of changes and of the
   Hub's operations. The file tree is one keystroke away (`g f`). Anonymous
   visitors are the exception: they get the README first, because they came
   to learn what the project is (§D.4.1).
3. **Every surface has an audience.** On GitHub, visibility is a
   repository setting. In Veil it is a property of every path
   ([secrets-and-visibility](guide/secrets-and-visibility.md#tiers-and-veilpolicy)),
   and of tags, descriptions, lines of work and embargoes. Each viewer
   receives a different slice (§4.7, §5.2). So the audience appears on
   every row, every diff and every comment, and one control in the top bar,
   the **lens**, names whose slice you are looking at (§D.3).
4. **Absence is always explained.** Veil never lets a partial view read as
   a deletion. Entries a reader cannot open are carried over (ARCHITECTURE.md
   §4 rule 6). "Now sealed" never reads as "deleted" (rule 4). A clone
   without a key says how many cloaked files it skipped
   ([teams](guide/teams-and-remotes.md#onboarding-a-teammate)). The Hub
   keeps that promise visually. Locked, withheld, embargoed and
   not-yet-fetched content each get a placeholder that says what it is, why
   you can't see it, and what would open it.
5. **Show where the plaintext came from.** On GitHub the server renders
   everything. On the Hub, closed content is decrypted in your browser or in
   `vl`, never on the server (§2.3). The UI marks decrypted content as
   opened on this device, with the key generation that opened it (§D.6.1).
   The point is to keep the zero-knowledge property visible.
6. **Reversible by default, irreversible by ceremony.** Veil's op log
   makes local actions undoable (`vl undo`, `vl op restore`). Some Hub
   actions cannot be taken back: revocation is forward-only, a release
   publishes a key, and a declassification reaches the public projection
   (§1.2). The UI sorts every action into *undoable*,
   *compensable* or *permanent*. Permanent actions get a preview of what
   becomes visible, and a passkey confirmation (§D.4.6).
7. **The command is the documentation.** `vl` is the complete client
   (§9.5). Every page and every button shows its `vl` equivalent, and the
   jump field accepts `vl` syntax (§D.8). The web is the CLI made visible,
   not a separate product.
8. **Calm security.** Most of what the Hub shows is normal: closed areas,
   visible metadata, unverified-but-ordinary browsers. Normal states are
   stated plainly and quietly. Red and blocking dialogs are reserved for
   integrity failures: a bad signature, a ring that does not verify, a
   client-pinning mismatch (§D.6.4).
9. **No social layer.** There are no stars, followers, contribution
   heatmaps or trending pages. The Hub is a workplace for mixed open and
   closed code, and a social layer would mostly leak who works on what (one
   of the metadata items in §3.3).

### D.2 Information architecture

#### D.2.1 Vocabulary

The UI uses Veil's words. Where GitHub has a near equivalent, the Hub's
word is chosen not to be mistaken for it.

| Hub UI says | Veil concept | Nearest on GitHub | Why not GitHub's word |
|---|---|---|---|
| **change** | a change id and its versions (ARCHITECTURE.md §5) | commit | A commit is one version; a change has many |
| **version** | a snapshot (`53414202`) | commit | Shown only where one exact version matters |
| **line** | a tag and the first-parent history behind it | branch | Veil has no branches. A tag follows rewrites and moves only on commit, merge and pull ([tags](guide/getting-started.md#tags)). The guide already says "line of work" and "one embargo per line" |
| **proposal** | `PullRequest` (§5.1) | pull request | Nothing is pulled. A proposal asks to move a tag so that it includes a stack of changes |
| **stack** | `PullRequest.stack`, bottom first (§5.1) | — | — |
| **round** | `Revision` (§5.1), one per push to a proposal | "force-pushed" | In `vl`, "revision" already means a `REV` expression such as `main--` ([getting-started](guide/getting-started.md#revisions)) |
| **sign-off** | a signed `Approval` per scope (§5.6) | approve | It is a signature, and it is per scope |
| **land** | client-side merge, then push (§5.7) | merge button | The Hub never merges; the lander's client does |
| **scope** | a ring (ARCHITECTURE.md §3) | team / repo permissions | A scope is a key, not a permission |
| **device** | an identity (§6.2) | SSH key | Every browser, laptop and runner is one |
| **Hub log** | server operations (§4.5) | audit log, activity | It is the remote's op log |
| **workspace** | a workspace (ARCHITECTURE.md §6) | codespace / worktree | Virtual: no directory |
| **run** | a CI or agent job on a runner (§7) | Actions run | — |

The data model and protocol names in §4–§8 (`PullRequest`, `Revision`,
`Approval`) stay. Only the UI and CLI words change. §5.7's
`vl hub pr merge 42` becomes `vl hub land 42`, and `vl hub pr` remains an
alias (§D.8).

#### D.2.2 Objects

```text
Org ─┬─ Accounts ── Devices (identities: native | web | runner)
     ├─ Teams ── mapped to scopes in repositories (§6.1)
     └─ Repositories ─┬─ Timeline: changes (each with versions) + Hub log operations
                      ├─ Lines: tags, each with its signed update chain (§4.6) and protection rules (§5.6)
                      ├─ Files: the tree at any revision, through the lens
                      ├─ Proposals: stacks, rounds, threads, sign-offs
                      ├─ Scopes: rings, members, ring log, checkpoints, grant requests
                      ├─ Embargoes: records, deadlines, release mode
                      ├─ Workspaces & runs: shared workspaces, agent and CI runs (UX addition, §D.4.7)
                      └─ Policy: .veilpolicy rendered as rules, tiers and audiences
```

#### D.2.3 Navigation

* **The top bar** holds four items: the org switcher; the **jump field**
  (`/`), which accepts revisions (`main--`, `yl`, `fix-cve@`) and `vl`
  commands; the **lens** chip (whose slice you see, §D.3); and the
  **device** chip (locked or unlocked, and the client's verification
  state, §D.6). There is no global search box: search over closed content
  runs in the worker (§9.4), so it lives in the jump field and says which
  scopes it searched.
* **A repository** has a narrow left rail, in this order: Timeline, Files,
  Proposals, Lines, Embargoes, Scopes, Workspaces & runs, Hub log, Policy,
  Settings. Every item has a `g`-chord (§D.7.6). The rail replaces GitHub's
  horizontal tab strip. The order follows how often members use each
  surface, not GitHub's "Code first".
* **An inspector** on the right of every page shows facts about the
  selected object: its audience, what the Hub can see of it, its signature,
  who decrypted it where, and the equivalent `vl` command. It is the one
  place for the trust facts (§D.6), so they don't clutter the main column.
* **URLs** *(UX addition)*: `/acme/app` (timeline), `/acme/app/c/yltznuyx`
  (a change), `/acme/app/c/yltznuyx/53414202` (one version),
  `/acme/app/@main` (a line), `/acme/app/@main/files/src/app.py`,
  `/acme/app/p/42` (a proposal), `/acme/app/scopes/ops`,
  `/acme/app/embargoes/77932133a2`, `/acme/app/log/<op>`,
  `/acme/app/ws/fix-cve`, `/acme/app/r/<revision>` (resolved by the
  client). **Paths of sealed files never appear in the URL path.** They go
  in the fragment (`/acme/app/@main/files#p=deploy/prod.yml`), which
  browsers never send to the server. The Hub can read cloaked file names
  until sealed trees ship (§3.3, C5), but its access logs, `Referer`
  headers and link previews should not collect them, and after C5 the
  rule is required anyway.

#### D.2.4 What replaces "branches", "commits" and "pull requests"

| GitHub page | Hub page | What is different |
|---|---|---|
| Code (tree + README) | **Timeline** for members; **README + public timeline** for anonymous visitors | History first; the tree is a tab |
| Branches | **Lines** | One row per tag: target change, cloak (a cloaked tag is listed only to its scope, as public remotes never receive it, [secrets-and-visibility](guide/secrets-and-visibility.md#cloaking-for-a-team)), protection rules, the signed update chain (who moved it, from what, when, §4.6), and whether it carries an unreleased embargo (one per line, ARCHITECTURE.md §7) |
| Commits | **Timeline**, filtered to one line | The graph with `vl log`'s glyphs, grouped by the Hub operation (push) that brought each change |
| Commit | **Change** | A change page with its versions (evolution log) and interdiffs between versions (§D.4.2) |
| Pull request | **Proposal** | A stack of changes, rounds, per-scope sign-offs (§D.5) |
| Security advisories, private forks | **Embargoes** | Embargoed merges on the real line (§8, §D.4.5) |
| Settings → collaborators | **Scopes** | Keys and signed membership logs, not ACL checkboxes (§D.4.4) |
| Actions | **Workspaces & runs** | Runs are sandboxed workspaces on runners that are scope members (§7, §D.4.7) |
| Audit log | **Hub log** | Every server operation, with its reversibility (§D.4.6) |

### D.3 The visibility lens

#### D.3.1 What a viewer can be shown

Every entry, change, description, tag, comment and log line is in exactly
one of these states for a given viewer. The state is computed by that
viewer's client from the tree labels and the rings. Except for "opened on
this device", it is also computable by the Hub, because projections are
key-independent (§2.2).

| State | Meaning | Grounded in | Shown as |
|---|---|---|---|
| **Public** | plaintext for everyone | `public` tier | `[public]`; quiet |
| **Public, unscanned** | `public!`: a deliberate exposure | [secrets-and-visibility](guide/secrets-and-visibility.md#tiers-and-veilpolicy) | `[public!]`, with "secret scanning off" in the inspector |
| **Opened here** | cloaked; you are a member; decrypted in this browser or in `vl` | §2.4 data flow | `[team]` plus the "opened on this device" margin (§D.6.1) |
| **Locked** | cloaked; you are not a member | `R` in `vl status` ([teams](guide/teams-and-remotes.md#onboarding-a-teammate)) | `[ops: locked]`, with name and size until sealed trees (C5), and "N entries in a sealed directory" after |
| **Locked, with a public fallback** | a public file edited on a cloaked line: you see its last public version | ARCHITECTURE.md §4 rule 4 | The fallback content, with a band: "a newer version exists for `team`" |
| **Device locked** | you are a member, but this browser's identity is locked (auto-lock, §9.3) | §9.3 | `[team: unlock]`, one action away; never the same chip as "locked" |
| **Embargoed, readable** | you hold the embargo's scope | ARCHITECTURE.md §7 | `[embargo 7793]`, with a toggle "show what the public sees now" (the pre-merge fallback) |
| **Embargoed, pre-merge view** | you don't hold the scope: you see the pre-merge tree exactly | [embargoes](guide/embargoes.md#what-the-public-sees) | The pre-merge content, with a band naming the embargo, its scope and its deadline (all public metadata) |
| **Withheld** | history the Hub won't serve you yet (an unreleased fix's own line) | §4.5 check 11; `(withheld)` in `vl log` | A dotted node in the graph: "merges 2be318b2 (withheld until release)" |
| **Not fetched yet** | the client hasn't downloaded it (partial history, §9.7) | C7 | A skeleton, never a lock. The two must not look alike |
| **Does not open** | ciphertext fails to authenticate, or a ring fails to verify | ARCHITECTURE.md §3 ("A ring that fails to verify gives no keys at all") | A Stop state (§D.6.4) |
| **Device-only** | isolated: never in history, never on the Hub | `isolate` tier | Never in trees (the Hub cannot know of them). Shown only in the Policy view, as rules: "`*.local.json` stays on devices" |
| **Held at the gate** | a newly public blob failed the pre-publish scan on the server | §4.5 check 12 | `[held at gate]` on the proposal or Hub log entry, visible to maintainers |

**Locked is never silently absent.** A locked file keeps its row in the
tree, sorted where it belongs, with its name and size (both visible to the
Hub and to public remotes today, [secrets-and-visibility](guide/secrets-and-visibility.md#what-is-protected-and-what-isnt)),
its scope (or its opaque id `s-7f3a9c21` with "name sealed", §6.1) and one
action. That action is **Ask for access** for org members, which creates a
grant request (§6.1), and nothing for anonymous visitors. Every tree and
diff ends with a count line: "You see 1,204 of 1,260 entries. 56 are in 2
scopes you are not in." A locked file in a diff shows its size before and
after (sizes are metadata, §3.3) and **no line counts**. The Hub doesn't
know them, and the UI never invents them.

#### D.3.2 The lens chip and "preview as"

The lens chip in the top bar names the audience the page is rendered for,
by default your own: `Seeing as you · public + team + ops`. Opening it gives
**Preview as** *(UX addition)*:

* **Public** renders the page as the public renderer serves it. It is not
  simulated: the client fetches the public projection itself, which is
  exactly what a `--public` remote holds (§2.2).
  This is the view to check before landing a declassification.
* **A member of scopes…** renders with a subset of your own scopes, for
  example "what a `team` member outside `ops` sees". The subset is computed
  in your client from the same labels.
* **A person** (admins) renders with that person's audience (§4.7). Parts
  that person could read and you can't are shown as locked *to you*, with a
  note: "bob can read this; you can't". Preview never opens anything.

While a preview is active, the whole page gets a coloured frame and a
pinned banner, "Previewing as: public", with Exit (`Esc`). This prevents
signing or commenting in the wrong frame of mind. Sign-off and land are
disabled during previews.

#### D.3.3 One page, three viewers

`acme/app`, files at `main`. Alice (member of `team` and `ops`), Dan (a
`team` member outside `ops`) and an anonymous visitor look at the same
directory. `main` carries an embargoed fix in `team` that touches
`parser.py`.

```text
ANONYMOUS ─────────────────────────────────────────────── lens: public
 acme/app  @main  pzkmnmrl…uqttozys   ✓ alice
 ┌─ This line carries an embargo (77932133a2, scope team). You see main's pre-merge tree.
 │  Its release is public metadata; when it happens, this view fills in by itself.
 ├────────────────────────────────────────────────────────────────────────
 │ [public]         app.py                  12 B
 │ [public]         parser.py               31 B     (pre-merge version)
 │ [team: locked]   secrets/notes.md        15 B
 │ [ops: locked]    deploy/prod.yml        1.3 KB
 │ You see 2 of 4 entries. 2 are in closed areas of this repository.
 └────────────────────────────────────────────────────────────────────────

DAN (team) ───────────────────────────────── lens: you · public + team
 │ [public]         app.py                  12 B
 │ [embargo 7793]   parser.py               58 B     ◐ opened on this device
 │ [team]           secrets/notes.md        15 B     ◐ opened on this device
 │ [ops: locked]    deploy/prod.yml        1.3 KB    Ask for access
 │ You see 3 of 4 entries. 1 is in a scope you are not in (ops).

ALICE (team, ops; scope admin) ────────────── lens: you · public + team + ops
 │ [public]         app.py                  12 B
 │ [embargo 7793]   parser.py               58 B     ◐   Public sees: pre-merge (31 B)
 │ [team]           secrets/notes.md        15 B     ◐
 │ [ops]            deploy/prod.yml        1.3 KB    ◐
 │ You see everything in this tree.
```

An **org owner who holds no scope** sees exactly what Dan sees for `team`,
or what the anonymous visitor sees, plus admin controls. Org ownership is
not a key (§6.1), and the UI never implies that it is. The settings page
says it in one line: "Org owners manage people and access to ciphertext.
Only scope members can read closed files."

#### D.3.4 Lines, descriptions, tags and comments

The lens applies to more than files:

* **Descriptions** sealed under a scope or an embargo render as
  `[cloaked:team]` / `[cloaked:embargo/77932133a2]` for non-holders, the
  same placeholders `vl log` prints
  ([embargoes](guide/embargoes.md#what-the-public-sees)).
* **Cloaked tags** are not listed to non-members at all, which is what
  public remotes do today. This is the one deliberate exception to "never
  silently absent". A cloaked tag's existence is itself protected, and the
  Lines page says so once: "Lines cloaked for scopes you're not in are not
  listed."
* **Sealed review threads** show as "3 threads in `ops`" with their
  states. Counts and sizes are metadata the Hub holds (§3.3); bodies are
  not.
* **Proposals with a scope audience** (§5.2) are hidden by the server from
  non-members. That is the second, server-enforced exception, needed for
  security fixes.

### D.4 Key screens

All screens share one frame: the top bar, the left rail, the main column
and the inspector. Wireframes show the main column and the inspector, and
omit the rail where space is short.

#### D.4.1 Repository home

**For members**, the home is the timeline of `main` (or the line last
viewed): changes grouped under the Hub operation that brought them, with
anything that needs you at the top. **For anonymous visitors**, the README
of the public projection comes first (rendered in the sandboxed content
origin, §9.6), then the public timeline.

```text
┌ acme/app ──────────────────────────────────────── [/ jump]  [lens: you · public+team+ops]  [device: unlocked ◐] ┐
│ Timeline  Files  Proposals  Lines  Embargoes  Scopes  Workspaces&runs  Hub log  Policy                          │
├──────────────────────────────────────────────────────────────────────────────────┬──────────────────────────────┤
│ @main ▾   Changes ● Operations ● Both                                            │ INSPECTOR  ·  @main          │
│                                                                                  │ Tag main → uqttozys af765f31 │
│ NEEDS YOU                                                                        │ Moved by alice ✓, op 7a1c,   │
│  ▸ Proposal 42 waits for an ops sign-off from you            round 3 · 2 changes │   2026-11-04 04:09 UTC       │
│  ▸ Scope ops: grant request for carol (laptop, native)            3f2a 91c0 ...  │ Chain verified (seq 41)      │
│  ▸ Embargo 7793 releases in 6 days (mode A: a key holder releases)               │ Protection: proposal needed, │
│                                                                                  │  sign-offs per touched scope │
│ YOUR SLICE   1,260 entries · you read all · 2 scopes · 1 embargo on this line    │ Hub sees: ids, tree shape,   │
│                                                                                  │  names+sizes of cloaked files│
│ ── op 7a1c · alice pushed to main · 2026-11-04 04:09 ─────────────────────────── │  (no sealed trees yet), times│
│  ○  uqttozys alice ✓ main af765f31 [embargo 7793]                                │                              │
│  │╲  Fix CVE-2026-1234                ⇠ merges pzkmnmrl, ooquruqt                │ vl log -r main               │
│  │ ○ ooquruqt alice ✓ [team]  Fix CVE-2026-1234: empty buffer crash              │   [copy]                     │
│ ── op 69e0 · dan pushed to main · 2026-11-03 17:20 ────────────────────────────  │                              │
│  ○  pzkmnmrl dan ✓ 781e94dc            Parser                    [public]        │                              │
│ ── op 6511 · alice granted dan → team (ring #4) ──────────────────────────────── │                              │
│  ◆  root                                                                         │                              │
└──────────────────────────────────────────────────────────────────────────────────┴──────────────────────────────┘
```

* "Needs you" lists only items addressed to you or to a scope you're in
  (§D.5.4). It is empty most of the time, and when it is, it disappears.
* "Your slice" is the visibility summary in one line. It links to the lens.
* **Operations** interleave with changes. A ring change or an embargo
  event is history too, and on GitHub it would be buried in settings.
* The graph glyphs are `vl log`'s (`@ ○ × ◆`, `⇠ merges`). Signature marks
  are `vl log`'s (`✓ ✓bob ? ✗ unsigned`). Someone who knows `vl log` can
  read the Hub, and the reverse.

#### D.4.2 A change and its evolution log

The change page is keyed by change id. It answers four questions: what the
change does now, how it got here, who touched it, and who can see which
part of it.

```text
 yltznuyx  Greet the world                                          [public] description
 author alice · current version 53414202 · signed ✓alice · on main · in proposal 42 (round 3)
 ─────────────────────────────────────────────────────────────────────────────────────────────
 VERSIONS (evolution log)                                    compare:  [v2] → [v4]
   v4  53414202  ✓alice   2026-11-04 04:14   pushed (op 7a1c) · proposal 42 round 3   ◀ current
   v3  95fbd25b  ✓bob     2026-11-04 03:50   pushed (op 6f02) · round 2 · rebased by bob, author alice
   v2  ecdb49a1  ✓alice   2026-11-03 18:02   pushed (op 6c11) · round 1
   ·   ab0323d9           not on the Hub      (a local version on alice's device; id only)
 ─────────────────────────────────────────────────────────────────────────────────────────────
 v2 → v4:  content edited in 1 file · rebased onto main (af765f31)
   [public]       main.rs        +1 −1      (rendered diff)
   [ops: locked]  deploy/prod.yml   changed between v2 and v4 (1.2 KB → 1.3 KB). ops content: you hold no key.
```

* **Versions** come from the evolution log (`vl evolog`,
  [getting-started](guide/getting-started.md#change-ids-and-snapshot-ids)).
  The Hub holds only the versions someone pushed: sync walks parents and
  trees, never `predecessors` (`remote.rs`), which are weak references even
  locally (`gc.rs` module docs). Versions that never left a device
  appear as ids with "not on the Hub", never as gaps.
* **"Rebased only" versus "edited"** is computed per file by object id,
  without keys, for sealed files too (§5.4, §5.6). A reviewer outside `ops`
  still learns *that* `ops` content changed between two versions, which is
  exactly what the sign-off carry-over rule needs.
* **Author versus signer** follows `vl show`: "signed by bob (rewritten;
  author alice)" (ARCHITECTURE.md §3, "Author vs. signer").
* **Divergent changes** (two visible snapshots with one change id) get a
  band at the top that lists both, with the `vl` command to settle it.
* A **conflicted** version shows `×` and lists conflicted paths. On an
  embargoed line no list is recorded (ARCHITECTURE.md §7 step 5), and the
  page says so instead of showing an empty list.

#### D.4.3 Review of a change that spans open and closed files

A proposal page has three columns: the **stack** on the left, the **diff**
grouped by audience in the middle, and the **sign-off matrix** in the
inspector. Here Dan (a `team` member outside `ops`) is looking at it.

```text
 Proposal 42 · land on main · by alice · round 3 of 3                       audience: everyone
 "Retry deploys on 503"                                                     [public] title
 ┌ STACK (bottom first) ┐ ┌ DIFF · change ksnqvlmo · round 2 → 3 ─────────────┐ ┌ SIGN-OFFS · round 3 ─────────┐
 │ ▸ ksnqvlmo  Retry…   │ │ PUBLIC                                            │ │ public  1 needed  ✓ dan      │
 │   rebased, edited    │ │  [public] app/retry.py        +24 −3   viewed ✓   │ │          (maintainer)        │
 │ ▸ wlmrptzn  Config…  │ │  [public] tests/test_retry.py +40      viewed ✓   │ │ team    1 needed  ✓ dan      │
 │   rebased only       │ │ TEAM                                ◐ opened here │ │          carried from round 2│
 │                      │ │  [team] secrets/notes.md      +2 −0               │ │          team files unchanged│
 │ round  1 2 [3]       │ │ OPS                                               │ │ ops     1 needed  —          │
 │ base main af765f31   │ │  [ops: locked] deploy/prod.yml  1.2→1.3 KB        │ │          you are not in ops  │
 │                      │ │   You can't review this file. 1 ops member must   │ │          ask: carol, erin    │
 │ POLICY               │ │   sign off. Its content changed in this round.    │ │          [Request ops review]│
 │ no .veilpolicy edits │ │ THREADS  2 open in public · 1 resolved in ops     │ │ ci/build ✓  (runner r-ops-1) │
 └──────────────────────┘ └───────────────────────────────────────────────────┘ │ ──────────────────────────── │
                                                                                │ Land: an ops member must     │
                                                                                │ land: main moved since round │
                                                                                │ 3 and also changed           │
                                                                                │ deploy/prod.yml (§5.5)       │
                                                                                │ vl hub land 42               │
                                                                                └──────────────────────────────┘
```

* **Grouping by audience** is the core of the screen. Public files come
  first, then each scope you hold, then locked scopes. Within a group, the
  order follows the tree. A locked group still lists every file with size
  changes (until C5), and says who can review it.
* **Rounds** are compared per change, matched by change id across rebases
  (§5.1). Each change in the stack is labelled *rebased only*, *edited* or
  *new / dropped / squashed away*, so a reviewer re-reads only what
  changed.
* **The sign-off matrix** has one row per touched scope (§5.3, §5.6). Each
  row shows who signed, whether the sign-off was carried over and why
  ("`team` files unchanged", from equal `(path, object id)` pairs), or why
  it was dismissed ("`deploy/prod.yml` changed in round 3"). Required
  statuses appear under it (§7.5).
* **Who can land** is computed before anyone clicks (§5.5): "you can land",
  "an `ops` member must land, or rebase the proposal first", or "blocked:
  sign-off missing for `ops`". Land runs in the browser's worker or in `vl`
  (§5.7), and the button says so: "Land on main (merges in this browser,
  then pushes)".
* **Policy changes** get their own tab whenever the stack edits
  `.veilpolicy` (§D.6.5).

#### D.4.4 Scopes and members, and the grant flow

```text
 SCOPES · acme/app                                                       vl scope list
 ┌─────────┬─────────┬────────┬────────┬───────────────┬──────────────────┬─────────────────────┐
 │ scope   │ you     │ gen    │ admins │ members       │ checkpoint       │ team (Hub) mapping  │
 ├─────────┼─────────┼────────┼────────┼───────────────┼──────────────────┼─────────────────────┤
 │ team    │ admin   │ 2      │ 2      │ 6 (9 devices) │ 3 h ago ✓        │ eng · in step       │
 │ ops     │ member  │ 4      │ 1  !   │ 3 (4 devices) │ 2 d ago ✓        │ sre · 1 behind      │
 │ s-7f3a… │ none    │ —      │ —      │ hidden        │ —                │ —                   │
 └─────────┴─────────┴────────┴────────┴───────────────┴──────────────────┴─────────────────────┘
  ! ops has one admin. Losing that device freezes the scope (guide: "Have at least two admins").
```

The **scope page** has three tabs:

1. **Members.** One row per person, expanded to their devices: name,
   fingerprint, device kind (native, web or runner, §6.2), role, the
   generation they were granted at, and whether their binding is proved
   (a short member id gives "unknown key" signatures,
   ARCHITECTURE.md §3). Actions: grant, revoke (rotates, and says so),
   make admin.
2. **Ring log.** `vl scope log` as a timeline: each change with its signer
   and signature, generation and time. Ring changes that need attention are
   flagged (§D.6.6).
3. **Requests.** Grant and revocation requests from team mappings (§6.1),
   new devices (§6.2) and "Ask for access" (§D.3.1), and the drift between
   team and ring. An admin acts on them in a batch: one confirmation, one
   signed change per scope and repository, pushed together (§6.1).

**Inviting**, as designed in §6.3. The point of the UI is to make the
out-of-band step impossible to skip by accident.

```text
 1  ADMIN: Invite to ops                          2  INVITEE opens the link
 ┌──────────────────────────────────────────┐     ┌──────────────────────────────────────────────┐
 │ Scope ops · role member · expires 72 h   │     │ alice invites you to scope ops in acme/app.  │
 │                                          │     │ This browser will get its own key; it never  │
 │ Your invite link (copied):               │     │ leaves this browser.                         │
 │ hub.example/i/9Q2F…#k=xxxxxxxx           │     │ [Use passkey]  then  [Accept invite]         │
 │                                          │     │ Your device fingerprint:                     │
 │ Send it yourself: chat, in person.       │     │   3f2a 91c0 7be4 d018                        │
 │ The part after # never reaches the Hub,  │     │   "harbor · velvet · comet · ninety"         │
 │ so the Hub can't swap in its own key.    │     │ Read these to alice when she asks.           │
 │ The Hub doesn't email invites. (§6.3)    │     └──────────────────────────────────────────────┘
 └──────────────────────────────────────────┘
 3  ADMIN: Confirm and grant
 ┌───────────────────────────────────────────────────────────────────────────────┐
 │ bob accepted (account bob, device "laptop", native).  Invite tag verified ✓   │
 │ Fingerprint 3f2a 91c0 7be4 d018 · "harbor · velvet · comet · ninety"          │
 │ Compare by voice or in person if the content matters.  [ ] I compared it      │
 │ [Grant ops to bob's laptop]   signs a ring change, then pushes                │
 │ vl scope grant ops veil1e75c…c00a --name bob                                  │
 └───────────────────────────────────────────────────────────────────────────────┘
```

* The "I compared it" box is not required, but an unticked grant is
  recorded in the Hub's metadata as "fingerprint not confirmed" and shown
  on the member row. Pressure through visibility, not through a blocker.
* The fingerprint words *(UX addition)* are a display encoding of the same
  hash as the hex, for comparison by voice. They protect nothing beyond the
  comparison itself, and they are not the 6-word invite code of §6.3, which
  needs a PAKE first (§11.3 item 3).
* After the grant, the invitee's page fills in without a reload: the
  clone-then-grant flow (ARCHITECTURE.md §6), with a short unseal transition
  (§D.7.5).

#### D.4.5 The embargo board

The board is a view of embargo records and their lines. Columns follow an
embargo's life:

```text
 EMBARGOES · acme/app                                   vl embargo list    [+ New embargoed fix]
 ┌ IN PREPARATION ────────┐ ┌ EMBARGOED ─────────────────┐ ┌ DUE ────────────────┐ ┌ RELEASED ──────────┐
 │ fix-cve2@ (cloaked:sec)│ │ 77932133a2 · scope team    │ │ (none)              │ │ 51c0aa9e3f         │
 │ proposal 44 (audience  │ │ on main · mode A           │ │                     │ │ released 10-28     │
 │   sec, hidden)         │ │ until 2026-11-11 04:09 UTC │ │ Mode A: due means   │ │ by erin ✓          │
 │ ! main carries 7793:   │ │   (Thu 05:09 your time)    │ │ "waiting for a key  │ │ public: ✓ mirror ✓ │
 │   lands after release, │ │ public sees: pre-merge tree│ │ holder's vl"; the   │ │ history filled in  │
 │   or on another line   │ │ withheld: 2 snapshots      │ │ Hub notifies them   │ │                    │
 │                        │ │ [Preview release] [Release]│ │ (§8.2)              │ │                    │
 └────────────────────────┘ └────────────────────────────┘ └─────────────────────┘ └────────────────────┘
```

* **One embargo per line** is shown, not just enforced: a line with an
  unreleased embargo is marked in Lines and on the board, and a fix being
  prepared for that line shows the same message `vl merge` gives
  ([embargoes](guide/embargoes.md#one-embargo-per-line)).
* **Release mode** is part of each card, with what it means: A ("released
  by the first key holder's `vl` after the deadline; the Hub notifies"), B
  ("released by the release service at the deadline"), C ("anyone can
  release once the drand round is out; cannot be postponed") (§8.1).
* **Preview release** shows the public projection as it would be after
  release: the files that become public and the history that fills in
  (§8.2). **Release** is a permanent
  action (§D.4.6).
* **Scope match** is checked when preparing: a fix workspace cloaked for a
  different scope than the planned embargo gets the guide's warning ("Use
  the same scope as the fix workspace's `--cloak`").
* **Outsiders get no board.** The embargoed merge appears in their timeline
  as it appears in `vl log` on a public clone, with id, scope and deadline,
  because that is public metadata. The Hub doesn't advertise it beyond
  that: no countdown and no list of upcoming publications (an open
  question, §D.9.2).

#### D.4.6 The Hub log and undo

The Hub log is the remote's op log: one entry per accepted push or Hub
action (§4.5). Members' own op logs stay on their devices (FORMAT.md §2),
and the page says so in its header: "This is the Hub's log. Your device's
log: `vl op log`."

Every entry carries a reversibility class *(UX addition; server support
noted per row)*:

| Class | Mark | Examples | What "undo" does |
|---|---|---|---|
| **Undoable** | ↺ | a tag move by push or land; closing a proposal; Hub settings, ACL and team changes; dismissing a sign-off | Restores the earlier state. For a tag, see *retraction* below |
| **Compensable** | ⇄ | a grant (→ revoke, which rotates); a revoke (→ re-grant at the current generation, which opens history again); a team mapping | Proposes the counter-action, and says what it cannot take back |
| **Permanent** | ■ | an embargo release; a land that declassifies cloaked files; a push that published public content; a rotation | Nothing. The entry explains what to do instead (rotate the underlying secrets) |

```text
 HUB LOG · acme/app                                                  vl hub log
 ↺  op 7a1c  alice   land proposal 42 → main  e7645a71 → af765f31          [Undo…]
 ⇄  op 7a0f  alice   ops: grant carol (laptop)   ring #9                    [Revoke…]
       carol's devices have not fetched since the grant: the key has not reached them yet
 ■  op 79d2  erin    release embargo 51c0aa9e3f   (public)                   permanent
 ↺  op 7911  dan     push main  5f50d8ae → e7645a71                         [Undo…]
```

* **Retraction for tag moves** *(UX addition; needs a server rule in §4.5
  check 1 and a signed tag update, §4.6).* Moving `main` back on the Hub
  does not move it on the clones that already pulled. Their next `vl push`
  would fast-forward it again, because tags fast-forward
  ([teams](guide/teams-and-remotes.md#push-and-pull)). So undoing a tag move
  records the undone target as **retracted**: the Hub refuses to
  fast-forward that tag onto a retracted snapshot unless the pusher forces
  it, and members who pulled it get a notice ("main was moved back by
  alice; your local main is ahead"). The undo dialog says all of this
  before it acts.
* **"Not yet delivered"** for grants uses metadata the Hub has anyway (who
  fetched what, §3.3). If the grantee's devices haven't fetched since the
  grant, a revoke is close to a clean undo. If they have, the dialog says
  that they hold the key for everything up to now (forward-only,
  [teams](guide/teams-and-remotes.md#removing-a-teammate)).
* **Permanent actions get a ceremony, not a typing test.** The ceremony is
  a publication preview: the public projection before and after, the
  files and the history that fills in. The user
  confirms with a passkey user-verification, which is needed anyway to
  sign. There is no "type the repository name" dialog.
* In the browser, actions are a local transaction followed by a push (land,
  release, ring changes). The worker's own repository has an op log too, so
  a failed push leaves nothing half-done, and the UI offers "Retry push" or
  "Discard local change" (`vl undo` in the worker).

#### D.4.7 Workspaces and agent sandboxes

In 1.0, workspaces are entries in a device's view. Only tags travel on push
([teams](guide/teams-and-remotes.md#push-and-pull)), so the Hub cannot see
anyone's workspaces today. The proposal *(UX addition; needs a server-side
ref namespace like `pr/<n>/…` in §5.1)*: a member may **share** a workspace
to the Hub as `ws/<account>/<name>`, a server-side ref that is not a tag,
never reaches public remotes, and keeps the workspace's cloak.
Shared workspaces do three jobs: hand-off between devices, "look at this"
without opening a proposal, and a target for agent runs.

A **run** is a job on a runner (§7.2): an ephemeral workspace over snapshot
S (`Repo::ephemeral_workspace`, ARCHITECTURE.md §6) runs a command, and the
result is recorded as a new change on top of S, as
`vl ws exec --ephemeral` does today
([workspaces](guide/workspaces-and-agents.md#one-shot-runs---ephemeral)).
CI runs and agent runs are the same object. They differ only in what
happens to the result: CI reports a status, and an agent run offers its
change as a proposal or adds it to a shared workspace.

```text
 WORKSPACES & RUNS · acme/app
 SHARED WORKSPACES
  fix-cve@   alice   [cloaked:team]  ooquruqt  "Fix CVE-…" (sealed)   updated 2 h ago   [Open] [Propose]
  docs@      dan     public          tnqynyzv  "Rewrite guide"        updated 1 d ago   [Open] [Propose]

 RUNS
  ● agent "lint fixes"  on main (af765f31)  runner group: hub-hosted (public projection only)
      result  zsspmtrn  "agent: lint fixes"  +3 files
      held back  2 files at paths cloaked for ops: this runner holds no ops key, so they were not recorded
      quarantined  1 file: leaked.txt (injected-isolated-secret)
      [Review as proposal]  [Discard]                    vl hub run --ephemeral -r main -- cargo fmt
  ✓ ci/build            on proposal 42 round 3  runner r-ops-1 (member of ops)  log sealed for ops ◐
```

* **What a run could see** is its first fact: hub-hosted runners get the
  public projection only, and self-hosted runners get the scopes they are
  members of (§7.1). An agent that edits files it cannot seal has those
  edits held back (`BuildReport::cloak_failures`, ARCHITECTURE.md §4 rule
  4), and the UI lists them as "held back", never as "failed".
* **Quarantine is legible.** A run that writes a secret, or a copy of an
  injected one, shows the file and the scanner rule
  ([workspaces](guide/workspaces-and-agents.md#with-isolated)). This is
  Veil's most distinctive safety net for agents, and on GitHub it would be
  invisible.
* **Run logs** are sealed for the job's scope (§7.2), and they open in the
  browser like files.
* The UI repeats the guide's caution where it matters: a sandbox isolates
  files, not processes. Untrusted agents belong on ephemeral runners
  ([workspaces](guide/workspaces-and-agents.md#sandboxes)).

#### D.4.8 Onboarding: "unlock this device"

Three distinct states, never conflated: **signed in** (account, passkey),
**unlocked** (this browser's identity decrypted into the worker, §9.3) and
**granted** (scopes have wrapped keys to this device).

```text
 FIRST VISIT TO A REPOSITORY YOU BELONG TO
 ┌─────────────────────────────────────────────────────────────────────────────────┐
 │ Set up this browser                                                    step 2/3 │
 │                                                                                 │
 │ ✓ Signed in as bob (passkey)                                                    │
 │ ▸ Create this browser's key                                                     │
 │     Closed files are decrypted here, in this browser. To do that, it needs its  │
 │     own key. The key is created here, locked with your passkey, and never sent  │
 │     to the Hub.                                                                 │
 │     [Create key with passkey]       (no passkey PRF? use a passphrase instead)  │
 │ · Ask for access                                                                │
 │     Your laptop (native) is a member of team, ops. This browser is a new device:│
 │     an admin must grant it, like any device. (§6.2)                             │
 │     [Request team]  [Request ops]                    ops is native-only: use vl │
 └─────────────────────────────────────────────────────────────────────────────────┘

 LATER VISITS                                      WHILE WAITING FOR A GRANT
 [device: locked ●] → [Unlock with passkey]        [team: requested · alice notified]
 Locked: closed content is cleared from the page;  Public content and metadata work
 public content stays.                             normally.
```

* The **device chip** in the top bar always shows the state: `locked ●`,
  `unlocked ◐ (locks after 15 min idle)`, or `no key in this browser`.
  When the device auto-locks, plaintext is removed from the page, not
  merely hidden.
* **Native-only scopes** (§9.5) are named at the request step, with the
  `vl` path offered instead, so nobody waits for a grant that policy
  forbids.
* **The CLI path** *(UX addition)*: `vl hub login` shows a short pairing
  code and opens the browser. The account confirms with its passkey, and
  `vl` signs the identity registration statement (§6.2). The device's
  identity is the one `vl identity show` prints.
* **Link device** (§6.2, optional) appears only when org policy allows it,
  with the short-code comparison on both screens.

#### D.4.9 Org settings

Org settings group by who is trusted with what. Each group says what
enforces it: the Hub, clients, or cryptography.

```text
 ORG · acme · settings
 People          accounts, teams, invitations                                   enforced by: Hub
 Scope mapping   team → scope in repos, drift per repository                    Hub requests, admins sign
 Roles           Org owners manage people and access to ciphertext.
                 Only scope admins can grant keys; only members can read.        cryptography
 Devices         web identities may not be admins [on]; native-only scopes [ops, prod]   admins' clients
 Governance      minimum admins per scope [2]; hold admin changes for a 2nd admin [off]   Hub (not proof
                 break-glass identity [not set]                                  against a compromised Hub)
 Publishing      pre-publish gate: [reject] / quarantine for review (§4.5 check 12)        Hub
 Embargoes       modes allowed: A [on] B [off] C [off]                           §8
 Scope names     opaque by default [on] (§6.1)                                   Hub
 Runners         groups, identities, the scopes they are members of              cryptography
 Offboarding     [Offboard a person…]                                            §6.5
 What the Hub sees   this org's metadata exposure, specific and current          (read-only)
```

* **Offboarding** is the §6.5 sequence as a checklist with live progress:
  Hub steps (sessions suspended, serving stopped) tick immediately, admin
  steps wait with the name of each admin who can act, and the rotation
  list is decrypted and secret-scanned in the admin's browser (§6.5 step
  5).
* **What the Hub sees** *(UX addition)* turns §3.3 into a concrete page for
  this org: "The Hub can read the names of 214 cloaked files in 9
  repositories, because sealed trees are not enabled; member names of 12
  scopes; who fetched what and when." Each row links to the setting or
  roadmap item that reduces it (opaque scope names, C5, C6). The page tells
  the truth in one place, so no other page has to oversell.

### D.5 Review and collaboration model

The Hub's proposals are built on §5. This section covers how they feel,
and why they don't follow GitHub's choices.

#### D.5.1 A proposal moves a tag

A proposal says: *move `main` so that it includes this stack*. Its header
always shows the tag and the stack (`land on main · 2 changes`), never a
branch-to-branch arrow. A proposal can be opened from a shared workspace,
from a run, or from the CLI (`vl hub propose -r @- --onto main`, *UX
addition*). The stack is the chain of changes between the target and the
named revision. Outside contributors propose against the public
projection (§1.3), and their stack is public-only by construction (§3.2,
"Outside contributor").

#### D.5.2 Stacks are first-class

* Each change in the stack is reviewed on its own (`]` / `[` move between
  changes). Sign-offs cover the whole round, as the `Approval` statement
  signs every head (§5.6), and the UI shows that as "signs all 2 changes".
* **Landing part of a stack** (the bottom k changes) *(UX addition; needs
  §5.7's server check to accept a prefix of the signed heads)* lets a long
  stack land in pieces without being split into new proposals.
* Reordering the stack is not a web action. It is a rewrite, done with
  `vl rebase` and pushed as a new round. The web shows the command.

#### D.5.3 Rounds, not force-pushes

Every push to a proposal is a round (§5.1). The default view is **since
your last sign-off or visit**, per change: *rebased only* changes are
collapsed with a one-line reason ("same content, new base"), and *edited*
changes open on the interdiff between your last round and the current one.
Sealed files take part through object ids: a non-member learns "`ops`
content changed in round 3", and nothing more (§5.3).

#### D.5.4 Sign-offs are per scope, and you sign what you read

* Requests go to **scopes, not people**: "needs a sign-off from `ops`".
  Any `ops` member can pick it up from their "Needs you" list. A person can
  still be asked by name, but the requirement is the scope's (§5.6).
* The sign-off control for scope S is enabled only after the client has
  rendered every S file of the round *(UX interpretation of §5.6: "the web
  client signs an approval for S only if it decrypted and showed the S
  diff")*. A reviewer who wants to vouch for the public part only signs
  `public`, which the UI offers as an explicit choice ("sign public only").
* A sign-off shows as a **stamp**: signer, device, scope, round, time, and
  "verified by your client" (each viewer's client checks the signature and
  ring membership itself, §5.6). It is not a green check mark.
* Carry-over and dismissal are explained in words on every stamp (§D.4.3).
  "Stale review" is not a mysterious state.

#### D.5.5 Threads anchored across rewrites

Threads are anchored to `(change id, path, lines)` (§5.4) and have four
visible states: **current**, **moved** (re-anchored, with "re-anchored by
carol's client" and the version it moved from), **outdated** (waiting for
a reader with the key to re-anchor), and **sealed** (you can't read the
file, so you see "1 thread in `ops`, resolved"). A comment on a sealed file
is sealed under that file's scope (§5.4). The composer shows the audience
before you type: "Visible to `ops` members". A comment on a public file in
a proposal whose audience is a scope gets the same label, so nobody writes
for the wrong audience.

**Suggested edits are changes** *(UX addition)*. "Suggest" on a line
creates a small change on top of the commented change, authored by the
reviewer and pushed into the proposal's next round as a separate change.
The author takes it with `vl squash -r <suggestion>` or the web's "Fold in"
button, or abandons it. It is Veil's own vocabulary, and the reviewer gets
credit in the evolution log.

#### D.5.6 Landing, embargoes and outside work

* **Land** offers the strategies the protection rules allow: merge,
  fast-forward or rebase (§5.7). Before it runs, it shows who can land and
  why (§5.5), and what the public projection gains: "publishes 3 files from
  scope `team`" for a declassification (§5.7).
* **Land under embargo** is a variant of land, available when the
  proposal's audience is a scope. It asks for the deadline and the release
  mode, and checks scope match and one-embargo-per-line before anything is
  signed (§5.7, §8).

#### D.5.7 What is deliberately not GitHub's

| GitHub | Hub | Reason |
|---|---|---|
| Pull request from branch A to branch B | Proposal to move tag T over a stack | No branches; tags follow rewrites |
| "Force-pushed" event; reviews go stale wholesale | Rounds, compared per change id; sign-offs dismissed per scope | Change ids survive rewrites; sealing is deterministic (§5.6) |
| One "Approve" per reviewer | A signed sign-off per scope | Different people hold different keys |
| Reviewers requested by name | Requests to scopes | Any key holder may sign |
| Suggestion blocks applied as commits by GitHub | Suggested changes, folded in by `vl squash` | The server can't write closed files, and shouldn't write anything |
| Merge button on the server | Land, in your client | Merging closed files needs keys (§5.7) |
| Hidden private fork for advisories | Embargoed proposal on the real line | §8.5 |

### D.6 Trust and security UX

The Hub makes four kinds of trust facts visible: **content** (where
plaintext came from), **signatures** (who made what), **the client** (is
this page the real one) and **freshness** (is this the latest membership).
Each has one home, the inspector, and one compact form, a chip.

#### D.6.1 "Opened on this device"

Every pane that shows closed content has a thin margin mark ◐ and, in the
inspector:

```text
 Opened on this device
   deploy/prod.yml · scope ops · generation 4 · key id 9c41e07a2b5d8f13
   fetched 1.3 KB of ciphertext from the Hub · decrypted in this browser's worker
   The Hub stored and sent only ciphertext; the plaintext above never left this device.
 What the Hub can see about this file
   its name and size (sealed trees are not enabled), its scope, when it changed, who fetched it
```

Public content says the opposite, just as plainly: "Public: the Hub and
everyone can read this." The contrast teaches the model better than a
tutorial. The key id is the public key id of the generation
(ARCHITECTURE.md §3, "key id"), safe to show.

#### D.6.2 Signatures

The marks are `vl log`'s, with the same meanings (ARCHITECTURE.md §3,
"Status"): `✓` good, `✓bob` good with a different signer, `?alice`
unknown key (valid, but no ring binds it to that member), `✗` bad,
`unsigned`. They differ in severity:

* `✓` is quiet;
* `?` and `unsigned` are a Notice. Signatures are advisory in 1.0
  ([secrets-and-visibility](guide/secrets-and-visibility.md#what-is-protected-and-what-isnt)),
  so this is a fact to know, not an alarm. Protection rules can still
  require signatures (§5.6), in which case land says so;
* `✗` is a Stop: a version whose signature does not verify is marked on
  every page it appears on, and land refuses it.

Each person also gets a **key mark** *(UX addition)*: a small geometric
glyph derived from their signing key and shown beside their name. Two
"alice" accounts with different keys look different at a glance. The mark
is never the only cue: the inspector shows the fingerprint.

#### D.6.3 The client: verified, unverified, native

The device chip carries the client state (§9.5):

| State | Shown as | Meaning |
|---|---|---|
| Native (desktop app or `vl`) | `native · 1.4.0 ✓` | Updates verified against the release signature |
| Web, verified by the pinning extension | `web · verified 1.4.0 ✓` | The extension matched every asset to the transparency log |
| Web, not independently verified | `web · served by hub.example` (neutral grey) | The usual case. You trust the Hub to serve the right code, which the inspector explains in two sentences. Native-only scopes are not unlockable here |
| Extension reports a mismatch | **full-page stop** | The page is blocked; nothing is unlocked. This is the one red full-page state |

The unverified state is not a warning. Most people will run it, and
treating it as an error teaches people to ignore warnings. It becomes a
Warning only where it matters: when the user tries to unlock a scope marked
sensitive, or to sign a ring change, the dialog says "Admin actions are
native-only in this org" or offers to continue in the desktop app.

#### D.6.4 Severity scale and copy

| Level | Colour | Used for | Example copy |
|---|---|---|---|
| **Info** | none (ink) | normal limits | "Names of cloaked files are visible to the Hub." |
| **Notice** | blue band | something to act on, at your pace | "carol asked for access to ops." |
| **Warning** | amber band + icon | a risk you can accept | "ops has a single admin." |
| **Stop** | red, blocking + icon | integrity failure | "This version's signature does not verify. It was not made by the key it claims." |

Copy rules: say what happened, what it means, and what to do, in that
order. Use words like "attack" or "compromise" only when verification
proves it, never as a guess. Never say "secure"; say what is protected and
against what, as the guide does.

#### D.6.5 A held-back policy change

`.veilpolicy` changes are review subjects of their own (§5.3). When a
proposal edits it, a **Policy** tab renders the edit as tier transitions,
not as a text diff:

```text
 POLICY CHANGES IN THIS PROPOSAL                                     vl policy show
  rule                 before            after                 effect
  .env                 isolate (built-in) public!             WEAKENS: devices keep their accepted
                                                                protection until each member runs
                                                                `vl policy accept`
  deploy/**            cloak ops          cloak opz            RE-SCOPES sealed files: needs ops; a merge
                                                                never takes such a rule from the merged
                                                                side (ARCHITECTURE.md §5)
  build/               —                  ignore               applies at once (strengthens)
  needs sign-off from: public, ops   (scopes whose paths the rules mention, §5.3)
```

This reuses the engine's own definitions: what counts as weakening
([secrets-and-visibility](guide/secrets-and-visibility.md#the-accepted-policy-when-an-incoming-change-is-held-back)),
what a merge refuses to take (ARCHITECTURE.md §5), and what applies at
once. The Hub cannot know any member's accepted policy, which is
device-local, so it never claims to. It says what *their devices* will do.

#### D.6.6 Ring changes that need attention

On the scope page and in the Hub log, ring changes are graded:

* **routine**: grant a member, rotate. Listed.
* **notable**: revoke, or grant to a web identity. Listed, with a dot in
  admins' "Needs you".
* **sensitive**: grant or remove an admin, demote an admin, grant to a
  device registered in the last 24 hours, grant without a confirmed
  fingerprint. With governance on (§6.7), the Hub **holds** the change
  until a second admin confirms, and the card says what it would do and
  who must confirm. With governance off, every member of the scope gets a
  one-line digest: "alice made dave an admin of ops".

**Freshness** (§6.6) appears as the checkpoint age on each scope ("3 h ago
✓"). When a scope's newest checkpoint is older than the window, the chip
turns into a Warning: "New ops content can't be sealed until an admin
checkpoints the ring (newest: 9 days ago)." A gossip mismatch (two members
hold different ring heads) is a Stop for that scope, with what each side
holds.

#### D.6.7 What we will not do

* No "encrypted" padlock theatre on pages that hold public content.
* No security score. It invites gaming and hides the trade-offs that §3.3
  states.
* No silent auto-acceptance of anything security-relevant on the user's
  behalf. The web never runs the equivalent of `vl policy accept` for
  anyone.

### D.7 Visual language

#### D.7.1 Direction: a ledger, not a dashboard

The Hub looks like a well-set ledger: light by default (with an equal dark
theme), typographic, few boxes, hairline rules between entries, generous
line spacing in prose and tight spacing in lists. Change ids, the most
important identifiers, are set as typographic elements in monospace,
with the shortest unique prefix in bold (*UX addition*, like the unique
prefix `vl` accepts, [getting-started](guide/getting-started.md#revisions)).

How it differs from its neighbours:

| | GitHub | GitLab | Linear | Veil Hub |
|---|---|---|---|---|
| Structure | horizontal tabs, file tree first | heavy left sidebar, many menus | issue-centric lists | narrow rail, timeline first, inspector of facts |
| Mood | busy, social (avatars, counters, stars) | dense, enterprise | dark-first, glossy, minimal | calm paper-and-ink, no social chrome |
| Colour | green/purple/red state badges | orange/purple brand | purple gradients | ink neutrals; colour reserved for audience and severity |
| Identity marks | avatars | avatars | avatars | names with a key mark (§D.6.2); avatars optional and small |

#### D.7.2 Typography

* **UI:** Atkinson Hyperlegible Next. It is open-licensed, designed for
  character distinction (`l I 1`, `0 O`), and used by none of the three
  products above. **Ids, paths and code:** Atkinson Hyperlegible Mono by
  default, user-selectable.
* Tabular figures everywhere numbers align (sizes, times, generations).
* Base size 14 px in compact density, 15 px in comfortable. Three densities,
  compact by default, because members live in lists.

#### D.7.3 Colour encodes audience, never alone

Every state from §D.3.1 has **an icon, a pattern, a text label and a
colour**. Remove the colour and nothing is lost.

| State | Icon | Pattern / border | Label | Hue family |
|---|---|---|---|---|
| Public | open aperture | none | `public` | ink (no hue: openness is the default) |
| Public, unscanned | aperture with a bar | none | `public!` | ink, with a Notice dot |
| Opened here (scope S) | key | solid left rule | `S` | the scope's hue |
| Locked (scope S) | closed padlock | diagonal hatch | `S: locked` | the scope's hue, desaturated |
| Device locked | padlock with a person | dotted hatch | `S: unlock` | the scope's hue, desaturated |
| Embargoed | hourglass | dashed outline | `embargo <id>` | amber |
| Withheld | — | dotted outline, hollow node | `withheld` | ink, light |
| Not fetched | — | skeleton shimmer (static under reduced motion) | (screen readers: "loading") | none |
| Held at the gate | shield with a bar | double rule | `held at gate` | amber |

* **Scope hues** come from a fixed set of eight hues, chosen so that
  adjacent hues stay distinguishable under the common colour-vision
  deficiencies. Scopes are assigned hues in creation order. With more than
  eight scopes, hues repeat but labels never do. An org can pin a hue to a
  scope.
* **Red** is reserved for Stop. Closed is not an error, so locked content
  is never red.
* **Diffs** keep the conventional added/removed meaning, with `+`/`−` in
  the gutter and word-level underlines, so colour isn't needed. A
  blue/orange palette is one setting away.
* Contrast: text 4.5:1 (WCAG 1.4.3), icons, borders and patterns 3:1
  against adjacent colours (1.4.11), in both themes.

#### D.7.4 Layout and responsiveness

* Desktop: rail (56 px) + main (fluid) + inspector (320 px, collapsible
  with `i`).
* Narrow screens and phones (the solo persona wants a phone, §1.3): the
  rail becomes a bottom bar of five items (Timeline, Proposals, Embargoes,
  Needs you, Jump), and the inspector becomes a sheet. Reading,
  commenting and signing off work on a phone. Ring changes and land
  default to "continue on a computer", because both are consequential and
  admin roles are native-only by default (§9.5).

#### D.7.5 Motion

One signature motion: **unseal**. When content becomes readable (unlock, a
grant arriving, an embargo release), its placeholder's hatch dissolves into
the content in about 150 ms. It marks a real state change the user should
notice. Otherwise motion is functional only: no parallax, no ticking
countdowns (deadlines read "in 6 days" and show the exact time on focus).
Under `prefers-reduced-motion`, every transition is instant.

#### D.7.6 Keyboard first, and WCAG 2.2 AA

* `/` jump: revisions (`main--`, `yl`, `fix-cve@`, `origin/main`), paths,
  proposal numbers, and `vl` commands (`vl show yl`,
  `vl diff --from main- --to main` open the matching page).
* `g t` timeline, `g f` files, `g p` proposals, `g l` lines, `g e`
  embargoes, `g s` scopes, `g w` workspaces, `g h` Hub log.
* Lists: `j`/`k` move, `o` open, `x` select. Review: `n`/`p` next/previous
  file, `]`/`[` next/previous change in the stack, `c` comment, `v` mark
  viewed, `s` sign off (opens the confirmation; never signs directly).
* `?` lists every shortcut. Single-key shortcuts can be turned off or
  remapped (WCAG 2.1.4).
* **WCAG 2.2 AA specifics.** Focus indicators are never hidden by the
  sticky top bar or the inspector (2.4.11). Targets are at least 24×24 px
  (2.5.8). Nothing needs a drag (2.5.7), including reordering and resizing.
  Sign-in and unlock use passkeys, so authentication needs no transcription
  or memorised puzzle (3.3.8). The invite code field accepts paste. Help
  lives in the same place on every page (3.2.6). Multi-step flows never ask
  for the same thing twice (3.3.7).
* **Screen readers.** The timeline is a list of entries, each with its
  change id, description, author, signature status and audience as text.
  The graph drawing is decorative and has a text equivalent per entry
  ("merges pzkmnmrl and ooquruqt; ooquruqt withheld"). Every chip's label
  is real text.

### D.8 CLI and web parity

Every page and action shows its `vl` equivalent in the inspector, with a
copy button, and the jump field accepts the same commands. Commands use
change ids and tag names, never URLs. Where a web action has no `vl`
equivalent yet, the inspector says so. The UI never shows a command that
doesn't exist.

| Web | `vl` today | `vl` with the Hub *(UX addition unless cited)* |
|---|---|---|
| Timeline, changes | `vl log` | — |
| Timeline, operations / Hub log | (device: `vl op log`) | `vl hub log`; `vl hub undo <op>` |
| Change page, versions | `vl show <change>`, `vl evolog -r <change>` | — |
| Interdiff between versions | `vl diff --from <snap> --to <snap>` | — |
| Files, file | `vl files -r main`, `vl cat PATH -r main` | — |
| Preview as public | — | `vl files -r main --as public` (computable without keys, C1) |
| Lines | `vl tag list` | `vl hub tag log main` (signed update chain, §4.6) |
| Policy view | `vl policy show`, `vl policy check PATHS` | — |
| Open a proposal | — | `vl hub propose -r @- --onto main` |
| Review a proposal | — | `vl hub review 42` (diffs per scope in the terminal) |
| Sign off | — | `vl hub sign-off 42 --scopes public,ops` (§5.6 has `--scopes public`) |
| Land | `vl merge … --into main` + `vl push` | `vl hub land 42` (§5.7's `vl hub pr merge 42`; `pr` stays an alias) |
| Comment | — | `vl hub comment 42 -r <change> PATH:LINE -m …` |
| Scopes, members, ring log | `vl scope list`, `vl scope log S` | — |
| Grant, revoke, rotate | `vl scope grant|revoke|rotate` | — |
| Invite, accept | (paste keys today) | `vl hub invite --scope ops`, `vl hub accept <link>` |
| Grant requests | — | `vl hub sync-grants` (§6.1) |
| Embargo board, release | `vl embargo list`, `vl embargo release ID` | `vl merge … --embargo --release-mode escrow` (needs C8) |
| Shared workspaces | `vl ws list|new|exec` | `vl hub ws share NAME` |
| Runs | `vl ws exec --ephemeral -r REV -- CMD` | `vl hub run --ephemeral -r REV -- CMD` |
| Unlock this device | `vl identity show` | `vl hub login` |
| Offboarding | `vl scope revoke` per scope | `vl hub offboard bob` (§6.5 batch) |
| Recover from a rogue admin | — | `vl scope recover` (§6.7) |
| Verify everything locally | `vl fsck` | `vl hub verify 42` (sign-offs, rings, statuses, tag chain) |
| Open the web page for a revision | — | `vl hub open [REV]` |

Web-only by nature: passkey management, billing, and the extension's
verification. The org settings page lists these as web-only.

### D.9 The MVP UI, and what to validate

#### D.9.1 What each phase ships

| Phase (§10.2) | UI it ships |
|---|---|
| **1. Smart remote** | Anonymous home (README + public timeline), files and change pages for the public projection (public renderer); Hub log (read-only); Lines with signed update chains; account sign-in; `vl hub login`; the "What the Hub sees" page |
| **2. Web client, read and administer** | Unlock this device; the lens with "preview as public / as a subset of my scopes"; member timeline and "Needs you"; change page with versions and interdiffs; files decrypted in the worker with "opened on this device"; scopes, members, ring log, requests; the invite flow with fingerprint words; grant, revoke, rotate; offboarding checklist; checkpoint chips; embargo board (mode A: notify, release, preview release); device chip with the unverified state |
| **3. Proposals** | Proposal page (stack, rounds, audience-grouped diff, sign-off matrix, threads, suggested changes), land and land under embargo, the Policy tab, held-at-gate review, Hub log undo with retraction (needs the server rule), reversibility classes; phone reading and sign-off |
| **4. CI** | Runs (CI first), sealed logs, statuses in the sign-off matrix |
| **5. Embargo service** | Release modes B and C on the board |
| **6. Hardening** | Extension-verified client state and the full-page stop; native-only scope UX; governance holds and second-admin confirmation; desktop app |
| **Later** | Shared workspaces and agent runs (needs the `ws/` ref namespace; phase 4's runner work is the base); preview as a specific person; partial stack landing |

**The MVP (phases 0–3, §10.3)** therefore includes the lens, the timeline
home, change pages with evolution, the audience-grouped review with
per-scope sign-offs, scopes with the out-of-band invite, the embargo board
for mode A, the Hub log with reversibility classes, and the trust chips
for content, signatures, device state and checkpoints. It excludes runs,
shared workspaces, release modes B and C, and the verified-client state.
Until phase 6, the device chip says "web · served by hub.example" for
every browser, which matches §10.3's "as trustworthy as the Hub".

#### D.9.2 Open UX questions to validate with real users

Tested with the owner's team first, then with open-source maintainers and
outside contributors (§1.3):

1. **Timeline home.** Do members orient faster from the timeline than from
   a file tree? Is README-first right for anonymous visitors? *Method:*
   first-click tests on both homes, then a week of diary use.
2. **Vocabulary.** Are proposal, round, sign-off and land understood
   without explanation by people who know Git? Does "line" help or confuse
   next to "tag"? *Method:* comprehension test on screenshots, before and
   after a one-paragraph explainer.
3. **Locked placeholders for outsiders.** Does seeing names of closed files
   (until C5) feel informative or like a tease to outside contributors? Should
   anonymous visitors see only the count line?
4. **Embargo discretion.** No countdown for outsiders is the current
   choice. Do downstreams want a public "something will be published" signal,
   and does that outweigh tipping off attackers?
5. **Sign what you read.** Will reviewers accept that a scope's sign-off
   unlocks only after every file of that scope has been rendered, or will
   they find it paternalistic on large generated files?
6. **Requests to scopes.** Does routing review to a scope instead of a
   person get faster responses, or diffuse responsibility?
7. **Undo of tag moves.** Do teams understand that a retraction moves the
   Hub's tag but not their clones', and is the notice enough?
8. **The unverified-client state.** Does a neutral grey chip strike the
   balance, or do users read it as "secure"? Do they install the
   extension once they understand it?
9. **Fingerprint comparison.** Do admins compare at all? Are words read
   aloud more reliably than hex groups? *Method:* observed invites with a
   planted mismatch, with consent.
10. **Tier glyphs and patterns.** Are the nine states distinguishable in
    greyscale, under simulated colour-vision deficiencies, at compact
    density, and with a screen reader?
10. **Preview as.** Does "preview as public" before landing a
    declassification catch mistakes in practice, and should it be
    mandatory for declassifying lands?
11. **Phone scope.** Is read + comment + sign-off the right phone feature
    set for the solo persona, or do they expect to release embargoes from a
    phone?

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
| **Metadata DB** | Accounts, identities, orgs, teams, repository ACLs, a mirror of each repository's view (tags, heads) for compare-and-swap, PRs, review threads (ciphertext bodies), signed approvals, invitations, CI jobs, audit log | **YugabyteDB** (owner decision, 2026-11-05: open source, Apache 2.0 core, Spanner-style distributed SQL) for the scaled Hub. The schema stays PostgreSQL-compatible SQL, so plain **PostgreSQL** runs it for local development, CI and small self-hosted teams. Both are in the Hub's test suite; the ref compare-and-swap is one conditional `UPDATE` with a serialisable retry wrapper. Verify the license file in the official repository before release; use the default Apache 2.0 builds, not the `-managed` ones. |
| **Web client** | All browsing and review of closed content; also signs approvals, ring changes and comments | TypeScript UI + `veil-core` compiled to WASM in a Web Worker (§9) |
| **Public renderer** | Pages for anonymous readers and search engines: the public projection only | Server-side, plaintext public content only |
| **CI coordinator** | Queues jobs, dispatches to runners, stores signed statuses and sealed logs | §7 |
| **Release service** | Releases embargoes on time without the Hub holding their keys before the deadline | Separate deployment and operator; §8 |

### 2.2 The key property this design rests on

**The public projection, and every per-viewer projection, is computable
without keys.** Veil already decides what a public remote receives by how
each object is *sealed*, never by which keys this replica holds
([ARCHITECTURE.md §8](ARCHITECTURE.md#8-synchronisation)). The
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
  id, [CRYPTO.md C1](CRYPTO.md#c1-sealed-objects-aes-siv-f3)).

This property must be kept as an engine invariant (§10.1).

### 2.3 What each component can and cannot see

| Component | Can see | Cannot see |
|---|---|---|
| API server, repo workers, DB, object storage | Everything in §3.3: public content in plaintext; ciphertext, labels, sizes and tree shape of closed content; rings (member ids, names, roles, generations, wrapped keys as ciphertext); embargo records; snapshot metadata; who did what when | Closed file contents, sealed descriptions, sealed review comments and CI logs, scope keys, embargo keys before release, identity secrets |
| Public renderer | The public projection, as a `--public` remote holds it | Anything sealed; rings (public remotes receive none, BUG-077, `remote.rs` module table) |
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
only because the Hub is then the one path to the public projection. A client-side hook alone can be bypassed.

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

The UI calls these *proposals*; how review looks and feels is
[§D.5](#d5-review-and-collaboration-model).

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
  ARCHITECTURE.md §7 step 6).
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
release (T)     → embargo released; advisory published;
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
| `zstd` (C library via `zstd-sys`) | packs (`pack.rs`) | builds for WASM only with a C toolchain for that target; large | try `zstd-sys` for WASM first; fall back to a pure-Rust decoder (dictionary support needed for delta entries) and have the browser write `stored` entries (pack kind 0) when it pushes |
| `getrandom` | `crypto.rs`, `identity.rs` | needs its WebCrypto (`wasm_js`) backend enabled for this target | build configuration |
| AES (AES-SIV) without AES-NI | `aes-siv`, `aes` | software AES: slower, constant-time bitsliced in RustCrypto | measure; WebCrypto has no AES-SIV, and composing one from WebCrypto's AES-CBC and AES-CTR would be a homemade construction, which Veil does not do (CRYPTO.md §1) |

**Status:** done for every row but the last: the `os` feature holds the
disk, SFTP, process and thread code, `zstd` the C library (packs are read
with `ruzstd` and written with stored entries without it), the clock is
injectable, and the lock has a no-OS mode (ARCHITECTURE.md §13). AES-SIV
runs as software AES; it has not been measured in a browser yet.

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
sealed under a device-local key, never uploaded. The screens are in
[§D.4](#d4-key-screens), and how the client's trust state is shown is
[§D.6](#d6-trust-and-security-ux).

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
* **Budgets to measure in phase 0**: WASM size (target ≤ 3 MiB compressed), AES-SIV and zstd throughput in WASM, time to first file
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
| C3 | **Clock injection** instead of `SystemTime::now()` / `Instant::now()` in the engine (`now_millis` in `lib.rs`, `store.rs`, `lock.rs`) | WASM (§9.1), trusted time for embargo deadlines (§8.2), deterministic tests | Low now, grows with every new call site. **Done:** `veil_core::clock` (`set_clock`, `monotonic`), ARCHITECTURE.md §13 |
| C4 | **A WASM target in CI**: `cargo check --target wasm32-unknown-unknown -p veil-core --no-default-features`, with threads, `DiskBackend`, SFTP and the lock behind features | §9.1 | Medium: unnoticed OS calls accumulate. **Done:** features `os` / `zstd` / `ruzstd` / `wasm`, CI job `wasm` (`scripts/check-wasm.sh`), ARCHITECTURE.md §13 |
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
| **5. Embargo service** | Deadline worker (mode A), escrow release service (mode B, needs C8), advisories and coordinated disclosure | 8–11 |
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
key holders, with Hub notifications), the pinning extension and the desktop app.
Until phase 6, the MVP is for the owner and their team only, with the web
client treated as "as trustworthy as the Hub" and sensitive scopes kept to
`vl`. The UI each phase ships is in [§D.9](#d9-the-mvp-ui-and-what-to-validate).

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
   on public remotes; readable names leak
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
9. **Pricing of storage.** Ciphertext does not deduplicate across scopes or
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
   today or planned, where what a public remote or a per-viewer audience
   receives depends on keys the sender holds? `Transfer::allowed`,
   `embargo_withheld` and `push_closure` are the places to read.
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
