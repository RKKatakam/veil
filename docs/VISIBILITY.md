# Who can see what: Veil's visibility model

> **Status:** decided by the owner on 2026-11-05. It is built by scale stream V.
>
> **This document is the source of truth.** Where `ARCHITECTURE.md`, `HUB.md`, a guide or an older design doc disagrees with it, this document wins, and the other one needs updating. Read this before designing anything about access, encryption, sharing, agents or the Hub.

## The model in one paragraph

You keep your whole codebase in **one repository**. For each path, `.veilpolicy` says **who can see it**:
- **public**: the whole internet, your own people included. This is the default.
- **A list of names**: groups or people. Only they can see the path, and the Hub checks before serving it.
- **`secret`** in front of the names: the same access, but the files are **encrypted**. This is for `.env` and keys, and it is the only encrypted case.
- **`local`**: the file never leaves this machine.

There is one concept, "who", and no separate company or team system.

## One rule shape: `PATH  WHO…`

```
# Who can see each path. Anything not listed is public: the whole internet.
internal/          members            # anyone who has access to this repository
billing/           finance            # only the finance group
research/pricing/  alice bob          # only these two people
infra/             ops carol          # a group plus a person
.env               secret members     # encrypted; all members can decrypt
deploy/keys/       secret ops         # encrypted; only ops can decrypt
notes/             local              # never leaves this machine
target/            ignore             # not tracked
```

| WHO | Who can see the path | How it's protected | Encrypted? |
|---|---|---|---|
| `public` (default) | **Anyone on the internet** (your own people included) | Served openly | No |
| names: groups and/or people | **Only those groups and people**, and agents acting for them | **Permission check:** the Hub never sends these files to anyone else | **No.** Plaintext, so the Hub can merge, search and blame them. |
| `members` | **Everyone who has access to this repository** | Same permission check | No |
| `secret` + names | Only those names (`secret members` = every member) | **Encryption.** The Hub stores ciphertext only and never holds the key. | **Yes. The only encrypted case.** |
| `local` | Only you, on this machine | Never committed, pushed or shared, with anyone or any agent | n/a (it never leaves) |
| `ignore` | n/a | Not tracked at all (`target/`, `node_modules/`) | n/a |

**Names:**
- **`members`** is the only built-in name. It means everyone with access to the repository, so you don't have to list everyone. It is not a "company" or "team" system.
- **Groups** (`finance`, `ops`) are named lists of people, defined on the Hub (or locally, for a repository without one).
- **People** are written by their user name (`alice`).
- **Agents** act for a person and see what that person sees, unless they are given less.

**Rules:**
- **The last matching rule wins,** so `internal/ members` can be followed by `internal/hr/ hr`.
- **Widening access needs permission.** Changing a path to `public`, or adding names to it, is checked on push by the Hub: it needs someone who already has access to the path **and** the right to manage access. The accepted-policy pin protects it locally. Otherwise anyone could add their own name.
- **The secret scanner** still runs on every non-secret file, and quarantines anything that looks like a credential.

### Defaults
- Every path is **`public`** unless `.veilpolicy` says otherwise.
- `.env`, `.env.*` and other shared-secret files default to **`secret members`**.
- **Personal private keys** (`id_rsa`, `id_ed25519`, `*.pem` private keys and similar) default to **`local`**: whoever holds a copy can impersonate their owner.
- A plain `public` rule can't weaken these defaults; that needs an explicit, deliberate command.

### One command: `vl access PATH WHO…`
```
vl access billing/ finance
vl access .env secret members
vl access docs/ public
vl access notes/ local
vl access PATH                 # show who can see PATH, and which rule decides it
```
`vl cloak`, `vl isolate` and `vl expose` remain as aliases, so nothing breaks.

## Embargoes: hidden changes, released later

A `.veilpolicy` rule is **per path**. An **embargo** is **per change**. It is for work like a security fix that must reach some people now, and the public only later.

1. **Fix it privately** on an embargoed line.
2. **Merge it everywhere, hidden:** `vl merge fix --into main --embargo-for security distro-partners --until 2026-12-01`.
   - **The names given** (groups, people, or outside partners such as distro maintainers) get the fix in `main`: its code, its message and its history. They can build, ship and install it.
   - **Everyone else**, including the public repository, sees `main` without it. They see no content, no message, no file names, and not even which files changed.
3. **Everything built on top stays embargoed** until release ("confinement"), so a later commit can't leak it by accident.
4. **Release:** `vl embargo release`, or automatically at the deadline. The fix, its history and its message then appear publicly. On the Hub, a separate release service publishes it on time, without the Hub holding the key before the deadline (`HUB.md` §8).

**Embargoes stay encrypted**, like `secret`, not just permission-checked:
- an unreleased security fix is a prime target;
- it often has to reach people outside the repository's members, over remotes the Hub doesn't control.

A patch is small, so decrypting it costs nothing noticeable.

## Who can see a PR

A PR (proposal) carries more than code: a title, a description, comments, reviews and a diff. These usually *describe* the code. So a PR is never shown in part.

- **An embargoed PR is visible only to the embargo's names.** For everyone else it **does not exist**: no title, no count, no "hidden PR" placeholder. Even its existence would signal that a security fix is coming.
- **Any other PR is visible only to people who can see every path it touches.** A PR touching `billing/` (finance) and `src/` (public) is shown only to finance.
  - Nobody gets a partial view: the text would leak what the hidden part is about.
  - To share the public part more widely, split the change into two PRs.
- **After an embargo's release,** its PR follows the rule above for the paths it touched.
- **Agents and CI follow the same rule:** an agent sees the PRs its person can see. A CI job sees only the PRs whose paths its runner has access to.
- **Search, notifications, activity feeds, counts and the API** all apply the same check. A PR you can't see never shows up anywhere, including in "N open PRs".

## Who gets what

| Reader | `public` | named paths | `secret` paths | `local` |
|---|---|---|---|---|
| Anyone on the internet (not a member) | ✅ | ❌ not sent | ❌ not sent | ❌ |
| A member, or an agent acting for one | ✅ | ✅ plaintext, **only for paths naming them** (or `members`). Others are not sent. | ✅ decrypted on their device, for secrets naming them | ❌ (only the owner's) |
| The Hub itself (and anyone who breaches it) | ✅ | ✅ (it serves them) | ❌ ciphertext only | ❌ never has them |
| A public mirror or remote | ✅ | ❌ withheld on push | ❌ withheld on push | ❌ |
| An SFTP remote (members-only by nature: only people with SSH access reach it) | ✅ | ✅ | ✅ encrypted | ❌ |

## Secrets: there is one secret, not one per agent

- **An API key is stored once,** encrypted. Every person, agent and machine with access uses that same key. **Nobody ever has to make new API keys for agents.**
- **A Veil identity is not an API key.** It is Veil's own key pair for a device, created automatically the first time Veil runs there. Its only job is letting that device open the secrets it has access to.
- **Becoming a member is the grant** for `secret members` files.
  - When a person or device becomes a member on the Hub, they get those secrets automatically.
  - The Hub never holds the secret key, so the first member's device that's online wraps it for the newcomer in the background, typically within seconds.
  - A setting can require manual approval of new devices instead.
  - Losing membership removes access to new secrets.
- **Narrower secrets are optional** (`deploy/keys/ secret ops`), and so is giving one agent or VM less than its person's access.

## Agents

| Where the agent runs | What you do | How it gets secrets |
|---|---|---|
| **On your own computer** (`vl ws exec`), any number of agents | **Nothing** | Through your machine's access. Secret files you can read are in the agent's sandbox like any checkout. For a run, `--with-isolated` (to be renamed `--with-local`) also copies in your `local` files, and `vl run -- CMD` passes vault secrets as environment variables. Anything the agent writes containing a secret is quarantined, never committed, and removed after the run. |
| **On a cloud VM or CI machine** | Approve the machine once, or let membership cover it | Synced encrypted, decrypted on that machine. Every agent on the machine shares its access. |
| **Over SSH, borrowing your laptop's access** (planned, like `ssh -A`) | Nothing permanent | The VM asks your laptop over the SSH connection for each secret it needs. Nothing is stored on the VM, and access ends when you disconnect. *Not built yet; planned for hardening.* |

**The limit.** An agent that has a secret can use it while it runs. That is the point of giving it the secret. Veil keeps secrets out of history and cleans them up after each run. It cannot stop a running program from misusing what it was given, so give risky agents test or limited keys.

## What changes from the previous design

- **One concept, "who can see this path", replaces the separate tiers** (cloak scopes, isolate, expose). A path is `public`, names, `secret` plus names, `local`, or `ignore`.
- **Restricted code is no longer encrypted.** It is protected by the Hub's permission check, so agents pay no decryption cost reading code, and the Hub can merge, search and blame it. Encryption is used only for `secret` paths and embargoes.
- **`.env` changes from isolated** (never shared) **to `secret members`** (encrypted and shared with members). Personal private keys stay `local` ("isolated" renamed).
- **On push, public remotes withhold** named and secret paths alike.
- **The Hub is zero-knowledge for secrets only,** not for all code. The Hub, and anyone who breaches it, can read named, non-secret code. This is the trade the owner chose, for simplicity and server-side features.
- **Unchanged:**
  - public remotes and mirrors never receive anything but public paths;
  - `local` files never leave the machine;
  - embargoes work as before (encrypted, per change, with confinement and timed release), with names as their audience.

## Questions to settle in stream V's design (not decided here)

- **How access shows up in history for people without it.** Their copy of a change shows the path redacted, and snapshot signatures must still verify for them (the Hub's per-viewer projection, `HUB.md`). Proposed: they don't see the names of paths they can't access either.
- **A change touching both `billing/` and code they can see.** Proposed: they see their part, and the change is marked as having parts they can't see.
- **The authority for named paths on push.** These files are plaintext, so the object can't prove its own audience, unlike encrypted content. Proposed: the accepted policy, applied by path, decides, whatever a snapshot's label claims. This is the main item for the threat review.
- **Repositories without a Hub** (SFTP only). Proposed: an SFTP remote counts as members-only, and groups are defined in a tracked, policy-protected file.
- **Migrating existing repositories.**
  - Cloaked paths become `secret` with the same names.
  - Converting a cloaked code path to plain names is an explicit command, never silent, because it removes the encryption.
  - Switching `.env` from isolated to `secret members` in an existing repository needs an explicit `vl upgrade` step that lists which files would start syncing.
