# Who can see what: Veil's visibility model

> **Status:** decided by the owner on 2026-11-05. It is built by scale stream V.
>
> **This document is the source of truth.** Where `ARCHITECTURE.md`, `HUB.md`, a guide or an older design doc disagrees with it, this document wins, and the other one needs updating. Read this before designing anything about access, encryption, sharing, agents or the Hub.

## The model in one paragraph

A company keeps its whole codebase in **one repository** on the Veil Hub.
- **Each folder or file** is public, company-only, or secret, set in `.veilpolicy`.
- **Public** paths are visible to anyone on the internet, like a public GitHub repository.
- **Company** paths are visible only to company members. The Hub checks membership before it serves them.
- **Secret** paths (`.env` and the like) are the only things that are encrypted. They are synced like any file, and decrypted only on the devices of people and agents who have access. By default that is everyone in the company.

## The four tiers

| Tier | Who can see it | How it's protected | Encrypted? | Example |
|---|---|---|---|---|
| **public** | Anyone on the internet | Nothing to protect; served openly | No | `src/`, `README.md`, docs |
| **company** | Company members only, people and their agents | **The Hub's permission check.** Non-members are never sent these files. | **No.** Plaintext on the Hub, so it can merge, search and blame them. | `internal/`, `billing/`, unreleased features |
| **secret** | Whoever has access to the secret. **By default, the whole company.** | **Encryption.** The Hub stores ciphertext only and never holds the key. | **Yes.** This is the only encrypted tier. | `.env`, `.env.*`, shared API keys, `deploy/keys/` |
| **isolated** | Only you, on this machine | Never committed, pushed or shared, with anyone or any agent | n/a (it never leaves the machine) | your own `id_rsa`, personal tokens, local overrides, notes |

And, as before, **ignored** paths (`target/`, `node_modules/`) are simply not tracked.

### Defaults
- Everything is **public** unless `.veilpolicy` says otherwise.
- `.env`, `.env.*` and other shared-secret files default to **secret**. **Personal private keys** (`id_rsa`, `id_ed25519`, `*.pem` keys and similar) default to **isolated**, because whoever holds a copy can impersonate their owner. A plain `public` rule can't weaken either default; that needs an explicit, deliberate command.
- The secret scanner still runs on public and company files, and quarantines anything that looks like a credential.

### `.veilpolicy` example
```
# everything not listed is public
internal/          company
billing/           company
.env               secret
deploy/keys/       secret
notes/             isolated
```

## Who gets what

| Reader | public | company | secret | isolated |
|---|---|---|---|---|
| Anyone on the internet (no account, or not in the company) | ✅ | ❌ not sent | ❌ not sent | ❌ |
| A company member, or an agent running for one | ✅ | ✅ plaintext | ✅ decrypted on their device | ❌ (only the owner's) |
| The Hub itself (and anyone who breaches it) | ✅ | ✅ (it serves them) | ❌ ciphertext only | ❌ never has them |
| A public mirror or remote | ✅ | ❌ withheld on push | ❌ withheld on push | ❌ |
| An SFTP remote (company-only by nature: only people with SSH access reach it) | ✅ | ✅ | ✅ encrypted | ❌ |

## Secrets: there is one secret, not one per agent

- **An API key is stored once,** encrypted. Every person, agent and machine with access uses that same key. **Nobody ever has to make new API keys for agents.**
- **A Veil identity is not an API key.** It is Veil's own key pair for a device, created automatically the first time Veil runs there. Its only job is letting that device open the secrets it has access to.
- **Joining the company is the grant.** When a person or device joins the company on the Hub, they get the company's secrets automatically. The Hub never holds the secret key, so the first company member's device that's online wraps it for the newcomer in the background, typically within seconds. A setting can require manual approval of new devices instead. Leaving the company removes access to new secrets.
- **Narrower access is optional.** A secret can be limited to a smaller group (e.g. `deploy/keys/ secret ops`), or one agent or VM can get less than full company access. That is the exception, not the default.

## Agents

| Where the agent runs | What you do | How it gets secrets |
|---|---|---|
| **On your own computer** (`vl ws exec`), any number of agents | **Nothing** | Through your machine's access. For a run: `vl ws exec AGENT --with-isolated -- CMD` (copies `.env`-type files in for that run only), or `vl run -- CMD` (as environment variables). Anything the agent writes containing a secret is quarantined, never committed, and removed after the run. |
| **On a cloud VM or CI machine** | Approve the machine once, or let company membership cover it | Synced encrypted, decrypted on that machine. Every agent on the machine shares its access. |
| **Over SSH, borrowing your laptop's access** (planned, like `ssh -A`) | Nothing permanent | The VM asks your laptop over the SSH connection for each secret it needs. Nothing is stored on the VM, and access ends when you disconnect. *Not built yet; planned for hardening.* |

**The limit.** An agent that has a secret can use it while it runs. That is the point of giving it the secret. Veil keeps secrets out of history and cleans them up after each run. It cannot stop a running program from misusing what it was given, so give risky agents test or limited keys.

## What changes from the previous design

- **"Cloak" becomes the secret tier.** Encryption is no longer the way to keep *code* private: company code is protected by the Hub's permission check instead. That means no decryption cost for agents reading code, and full server-side merge, search and blame.
- **`.env` changes from isolated** (never shared) **to secret** (encrypted and shared with the company).
- **A new company tier** (plaintext, enforced by the Hub). On push, public remotes withhold company paths exactly as they withhold secret content.
- **The Hub is zero-knowledge for the secret tier only,** not for all code. The Hub, and anyone who breaches it, can read company code. This is the trade the owner chose for simplicity and server-side features.
- **Unchanged:** public remotes and mirrors never receive anything but public paths, and isolated files never leave the machine.

## Questions to settle in stream V's design (not decided here)

- Is "company" one group, or can there be several (teams, departments) for company-tier paths? Proposed: one `company` group by default, with named groups allowed.
- The exact behaviour of an SFTP remote, which has no permission checks. Proposed: treat it as company-only, and refuse to push company paths to a remote marked public.
- How existing cloaked repositories migrate. Proposed: cloaked paths become secret. A repository can convert code paths from cloaked to company with an explicit command, never silently, because that removes the encryption.
