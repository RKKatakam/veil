# Secrets and visibility

Every path in a Veil repository has a **visibility tier**, decided by
`.veilpolicy` and by rules built into the engine. The engine enforces it
when it records a snapshot, so no command, merge or push can get around it.

1. [Tiers and `.veilpolicy`](#tiers-and-veilpolicy)
2. [Built-in secret rules](#built-in-secret-rules)
3. [The secret scanner](#the-secret-scanner)
4. [Quarantine](#quarantine)
5. [`vl scan` in CI](#vl-scan-in-ci)
6. [The vault: `vl secret` and `vl run`](#the-vault-vl-secret-and-vl-run)
7. [Cloaking for a team](#cloaking-for-a-team)
8. [The accepted policy: when an incoming change is held back](#the-accepted-policy-when-an-incoming-change-is-held-back)
9. [What is protected, and what isn't](#what-is-protected-and-what-isnt)

## Tiers and `.veilpolicy`

| Tier | Recorded? | Team remote gets | Public remote / GitHub gets |
|---|---|---|---|
| `public` (default) | plaintext, **secret-scanned** | it | it |
| `public!` | plaintext, **not** scanned | it | it |
| `cloak [scope]` | encrypted for the scope (default `team`) | ciphertext (members can read it) | nothing: the entry is withheld |
| `isolate` | **never**: local-only, kept in your device's vault | nothing | nothing |
| `ignore` | never, not even locally | nothing | nothing |

`.veilpolicy` is a tracked file at the root of the repository. One rule per
line, **the last matching rule wins**:

```text
# <pattern>        <tier> [scope]
secrets/            cloak team
config/prod/**      cloak ops
*.local.json        isolate
target/             ignore
tests/fixtures/     public!           # deliberate exposure, secret scanning off
```

Edit it by hand, or let `vl` append a rule:

```text
$ vl cloak config/
Added rule  config/                  cloak team
warning: 1 matching file(s) already exist in plaintext in earlier snapshots (e.g. config/prod.yml). New snapshots are protected; rotate any secrets they contain.
```

| Command | Appends |
|---|---|
| `vl cloak PATTERN… [--scope S]` | `PATTERN cloak S` (you must hold the scope's key) |
| `vl isolate PATTERN…` | `PATTERN isolate` |
| `vl expose PATTERN…` | `PATTERN public` |
| `vl expose --force PATTERN…` | `PATTERN public!` (also overrides built-in secret rules) |
| `vl ignore PATTERN…` | `PATTERN ignore` |

Inspect it:

```text
$ vl policy check .env cfg.js app.py
.env: isolated via built-in secret rule '.env'
cfg.js: public via default
app.py: public via default
$ vl files
public                   887  .veilpolicy
public                    12  app.py
cloaked:team              15  secrets/notes.md
```

`vl policy show` lists every rule, built-in ones first.

**Pattern details.** Patterns are globs (`*`, `**`, `?`, `[…]`, `{a,b}`), and
a trailing `/` means a directory. `\` escapes a character
(`config\[prod\].yml`, `my\ notes.txt`); `vl cloak|isolate|expose|ignore`
on an existing path escapes it for you. Built-in secret rules and
`cloak`/`isolate` rules ignore case (`.ENV`, `Secrets/`); `public`,
`public!` and `ignore` rules are case-sensitive.

**Policy rules fail safe.** A rule with an unknown tier, no tier, or an
invalid scope name is treated as `isolate`, with a warning.

**Changing a tier doesn't rewrite history.** Content recorded in plaintext
before you cloaked it stays readable in those older snapshots (`vl cloak`
warns, as above). Rotate any secret that was ever recorded in plaintext.

## Built-in secret rules

These come before your rules and **cannot be made public by a plain
`public` rule**, only by `cloak` (encrypted sharing) or an explicit
`public!` (`vl expose --force`):

```text
$ vl policy show
built-in      .env                     isolate
built-in      .env.*                   isolate
built-in      .envrc                   isolate
built-in      *.pem                    isolate
built-in      *.key                    isolate
built-in      *.p12                    isolate
built-in      *.pfx                    isolate
built-in      *.jks                    isolate
built-in      *.keystore               isolate
built-in      id_rsa                   isolate
built-in      id_dsa                   isolate
built-in      id_ecdsa                 isolate
built-in      id_ed25519               isolate
built-in      .netrc                   isolate
built-in      .pgpass                  isolate
built-in      .pypirc                  isolate
built-in      .git-credentials         isolate
built-in      *.tfstate                isolate
built-in      *.tfstate.*              isolate
built-in      .env.example             public
built-in      .env.sample              public
built-in      .env.template            public
built-in      .env.dist                public
.veilpolicy   target/                  ignore
.veilpolicy   node_modules/            ignore
```

A plain `public` rule on one of them is ignored, and every command warns
until you remove it:

```text
$ vl expose t.pem
Added rule  t.pem                    public
warning: policy tries to make built-in secret path t.pem public; ignored (use `public!` / `vl expose --force` to override)
$ vl policy check t.pem
t.pem: isolated via built-in secret rule '*.pem' (a `public` rule was ignored: use `public!`)
```

`vl undo` takes the rule back out.

## The secret scanner

Every **public** file is scanned when it is recorded, whatever its size or
encoding (binary and UTF-16 files included). It looks for:

| Rule | Finds |
|---|---|
| `private-key` | PEM private key headers (RSA, EC, DSA, OpenSSH, PGP, encrypted) |
| `aws-access-key-id` | `AKIA…`, `ASIA…` access key ids |
| `github-token` | `ghp_…`, `gho_…`, `ghs_…`, `github_pat_…` |
| `gitlab-token` | `glpat-…` |
| `slack-token` | `xoxb-…`, `xoxp-…` |
| `stripe-secret-key` | `sk_live_…`, `rk_live_…` |
| `anthropic-api-key` | `sk-ant-…` |
| `openai-api-key` | `sk-…`, `sk-proj-…` (high entropy) |
| `google-api-key` | `AIza…` |
| `jwt` | JSON Web Tokens |
| `url-password` | `postgres://app:<password>@db` |
| `generic-secret-assignment` | `password = …`, `API_KEY=…`, `JWT_SECRET: …`, `client_secret`, `<password>…</password>` and similar, with a credential-looking value |
| `injected-isolated-secret` | the value of an isolated file copied into a `ws exec` sandbox (see [Workspaces](workspaces-and-agents.md#with-isolated)) |

The assignment rule tries hard not to fire on code: references (`$X`,
`${X}`), placeholders (`<key>`), words (`settings.SECRET_KEY`) and
non-credentials (`password_hash`, `token_url`, `csrf_token`) don't count.

**Known misses** (see [`docs/BACKLOG.md`](../BACKLOG.md)): word-only
passphrases, weak passwords, credentials in XML attributes
(`<add key="DbPassword" value="…"/>`), camelCase generic tokens
(`githubToken: …`), and URL passwords that are words or numbers. The
scanner is a safety net, not a guarantee: keep real secrets in isolated
files or the vault.

Cloaked files are not scanned (they are encrypted anyway), and `public!`
paths are deliberately not scanned.

## Quarantine

A public file in which the scanner finds something is **quarantined**: it is
left out of the snapshot, and every command warns.

```text
$ echo 'k = "AKIAIOSFODNN7EXAMPLE"' > cfg.js
$ vl status
warning: cfg.js quarantined: looks like a secret (aws-access-key-id at line 1: AKIA…(20 chars)); not snapshotted. Fix it, or `vl cloak|isolate|expose --force cfg.js`
Working copy changes:
A .veilpolicy
A app.py
Workspace    : default
Working copy : @ wwttlpsq 7b1d03cc (no description set)
Parent       : zzzzzzzz 72edc798 (no description set)
Local-only (isolated; never snapshotted or pushed):
  L .env
Quarantined (secrets detected; kept local):
  Q cfg.js  (aws-access-key-id; never recorded)
```

* A **new** file is not recorded at all (`never recorded`).
* An **edit** of a tracked file is held back: history keeps the previous,
  clean version (`edit held back; history keeps the previous version`).
  Nothing is recorded as deleted.
* The file stays on your disk, untouched, and is backed up in your local
  vault.

Resolve it in one of these ways:

| If the file… | Do |
|---|---|
| should not contain the secret | Remove it from the file (read it from the environment or the vault instead). The next command records it |
| should be shared with your team, encrypted | `vl cloak cfg.js` |
| should stay on this machine | `vl isolate cfg.js` |
| is a false positive or a deliberate test fixture | `vl expose --force cfg.js` (`public!`: never scanned again) |
| has an edit you want to throw away | `vl restore cfg.js` puts back the recorded version |

```text
$ vl restore cfg.js
Restored 1 path(s) from wwttlpsq b226c41d app
$ cat cfg.js
k = process.env.AWS_KEY
```

## `vl scan` in CI

`vl scan` scans the working copy and **exits 1** if a public file holds a
secret. It also lists secrets in protected files, which are fine:

```text
$ vl scan
isolated  .env:1  url-password Xk29…(11 chars)
PUBLIC    cfg.js:1  aws-access-key-id AKIA…(20 chars)
found: 1 public file(s) contain secrets; they are quarantined from snapshots until cloaked, isolated or fixed
$ echo $?
1
```

`vl scan` needs a Veil repository, and a CI checkout from GitHub is a Git
checkout. Create a throwaway one: `vl init` keeps the `.veilpolicy` that is
checked out, and a temporary `VEIL_HOME` keeps the CI identity out of the
way:

```sh
export VEIL_HOME="$(mktemp -d)" VEIL_USER=ci
vl init > /dev/null
vl --no-snapshot scan
```

```text
PUBLIC    leak.js:1  aws-access-key-id AKIA…(20 chars)
found: 1 public file(s) contain secrets; they are quarantined from snapshots until cloaked, isolated or fixed
```

In a GitHub Actions step this fails the job on a hit. Note that `vl init`
in a Git checkout also records `.git/` (it is not ignored by default); that
is harmless in a throwaway CI repository, but see
[Troubleshooting](troubleshooting.md#vl-init-in-a-git-checkout-records-git).

## The vault: `vl secret` and `vl run`

Each repository has a **device-local, encrypted vault** in
`.veil/local/vault.sealed`, sealed with your identity. It is never synced.
Isolated and quarantined files are backed up into it automatically; you can
also store named secrets and run commands with them as environment
variables:

```text
$ vl secret import .env
Imported 1 secret(s) from .env
$ vl secret set API_TOKEN s3cr3t-value
Stored secret API_TOKEN in the local vault
$ vl secret list
API_TOKEN
DB_URL
$ vl run -- sh -c 'echo "db=$DB_URL token=$API_TOKEN"'
db=postgres://app:Xk29vLq8sPz@db/prod token=s3cr3t-value
```

| Command | Does |
|---|---|
| `vl secret set NAME [VALUE]` | Store a secret (reads stdin if `VALUE` is omitted, which keeps it out of your shell history) |
| `vl secret get NAME` | Print it |
| `vl secret list` / `vl secret rm NAME` | List names / delete one |
| `vl secret import FILE` | Import `KEY=VALUE` lines from a dotenv file (`export` prefixes and quotes are stripped) |
| `vl run -- CMD…` | Run `CMD` with every vault secret in its environment; exits with its status |

The vault is per repository and per device. A teammate's clone has its own.
Replacing your identity makes the vault unreadable until you re-key it
(`vl identity recover-vault`, see [Maintenance](maintenance.md#replacing-your-identity)).

## Cloaking for a team

A **scope** is a named group of identities that share a key. `vl init`
creates `team`, with you as its admin. A cloaked file is encrypted for its
scope's current key; only members can read it, and public remotes and Git
never receive it.

```text
$ vl scope list
team  admin  generation 0, 1 changes
    alice        admin  veil14ee1c25cc3089f6bc41d9eb126ae1a2aa15d541d374b9198b941e77c18d2d446 (you)
$ vl scope create ops
Created scope ops (you are its admin)
$ vl cloak 'deploy/*.yml' --scope ops
Added rule  deploy/*.yml             cloak ops
```

| Command (admins only, except `list` and `log`) | Does |
|---|---|
| `vl scope list` | Scopes, members, roles, key generation, and your access |
| `vl scope create S` | A new scope with you as its admin |
| `vl scope grant S PUBKEY --name NAME [--admin]` | Give an identity the scope's current key, which also opens earlier generations (so they can read history) |
| `vl scope revoke S PUBKEY` | Remove a member **and rotate** the key: new content is sealed with a key they never get |
| `vl scope rotate S` | Start a new key generation for the current members |
| `vl scope log S` | The signed membership log |

Changes to a scope are signed entries in a log that is synced with the
repository. **Push after every change**: members get the new keys on their
next pull. The full walkthrough of adding a teammate is in
[Teams and remotes](teams-and-remotes.md#onboarding-a-teammate).

```text
$ vl scope revoke team veil16a98…20
Revoked. Scope team rotated to key generation 1: new content is sealed with a key
the revoked identity never receives. Content they already decrypted cannot be recalled; rotate secrets.
Push to share the updated key ring.
$ vl scope log team
#0   2026-11-04 04:08:54 alice create scope (alice)
#1   2026-11-04 04:09:05 alice grant bob (member)
#2   2026-11-04 04:09:17 alice revoke bob → generation 1
#3   2026-11-04 04:09:17 alice rotate → generation 2
```

**Use the full public key** from `vl identity show` when granting. A short
member id works for encryption, but then their signatures show as unknown
(`vl` warns).

**Cloaked workspaces and tags.** `vl ws new NAME --cloak [S]` makes a
workspace in which everything recorded is cloaked, descriptions included.
`vl commit` there moves only tags cloaked under the same scope, never
`main` or another uncloaked tag. `vl tag set NAME --cloak [S]` makes a tag
that public remotes never receive.

**Visibility never widens by accident.** Rebase, `vl new`, squash, and
policy edits that arrive by merge keep sealed files sealed. Publishing is
explicit: `vl merge` of a cloaked line (secret-scanned; it lists what it
published) or `vl expose`.

> **Public files edited in a cloaked workspace.** A public file you *edit*
> in a cloaked workspace is recorded cloaked, together with its last public
> version. Anyone who cannot read the scope (a public remote, GitHub,
> teammates outside it) keeps seeing that last public version, never a
> deleted file, until you publish the work with `vl merge`. A file you
> cloak with `vl cloak` is different: hiding it is the point, so public
> readers stop seeing it.

## The accepted policy: when an incoming change is held back

`.veilpolicy` is shared, but isolated files exist only on your machine, so
**a policy change you did not make never weakens their protection
silently.** Your device keeps the policy you last accepted
(`.veil/local/accepted-policy`).

Say a teammate pushes `.env public!`, and you pull and rebase onto it:

```text
$ vl rebase -d main
Rebased mykuvxmu c13e04ed (empty) (no description set)
Updated 1 files, removed 0
  kept .env (local edit not in history, e.g. quarantined; left as is instead of being overwritten)
warning: 1 local file(s) keep the protection you accepted: .veilpolicy would weaken it, and that change came from a merge, pull, checkout or undo rather than your own edit (.env (isolate → public!)). Review it with `vl policy show`; apply it with `vl policy accept`

$ vl status
…
Policy change not accepted (protection kept; `vl policy accept` applies it):
  P .env  (isolate; .veilpolicy says public!)

$ vl policy show
…
Not yet accepted: .veilpolicy would weaken the protection of local files (they keep the protection you accepted on this device):
  .env: isolate → public!
Run `vl policy accept` to apply .veilpolicy in full.
```

Your `.env` stays isolated, and every command warns. Then either:

* **Reject it:** edit `.veilpolicy` to remove the rule and commit. Your own
  edits always apply at once.
* **Accept it:** `vl policy accept` applies `.veilpolicy` in full and lists
  the local files whose protection it weakens.

What counts as weakening: isolated → cloaked or public; cloaked → public or
another scope; `public` → `public!`; un-ignoring a built-in secret. New
`isolate` and `ignore` rules from others, and anything that strengthens
protection, apply at once. The check covers every route a policy arrives
by: merge, pull, checkout, rebase, Git import and undo.

## What is protected, and what isn't

The full threat model is in
[`docs/ARCHITECTURE.md`](../ARCHITECTURE.md#threat-model), and open issues
are in [`docs/BACKLOG.md`](../BACKLOG.md). In short:

**Protected:**

* Accidental commits of secrets: the built-in rules, the scanner and
  quarantine, with no ignore file to forget.
* Cloaked content, cloaked descriptions and cloaked tags never reach public
  remotes or Git. Readers of a team remote who are not in the scope get
  ciphertext only.
* Revoked members can't read **new** content: revocation rotates the key.
* Tampering: ciphertext is authenticated; key-ring changes and embargo
  records are signed and hash-chained; snapshot ids commit to their
  signatures.
* Hostile remotes: path traversal, writes into `.veil/`, deep nesting and
  terminal escape sequences in names are refused.

**Not protected (known limits in 1.0):**

| Limit | What it means for you |
|---|---|
| **File names, sizes and tree shape of cloaked files are visible** | A public remote shows `cloaked:team 15 secrets/notes.md (redacted)`: anyone can see that the file exists, its name and its size. Don't put secrets in file names |
| **Scope membership is visible** | Key rings are synced to every remote, public ones included: anyone with a clone of a public mirror can list each scope's member names and ids (`vl scope list`) |
| **Equality leakage** | Sealing is deterministic: two cloaked files (or versions) with identical content produce identical ciphertext, so an observer can tell they are equal |
| **Revocation is forward-only** | A revoked member keeps every key up to the revocation, so they can still read all history sealed before it, including unchanged files still sealed under an old generation, and anything they already decrypted. Rotate the underlying secrets |
| **Plaintext history stays** | Cloaking a path doesn't encrypt earlier snapshots. Git history imported from GitHub is public by definition |
| **Trust on first use** | A fresh clone accepts the first valid key ring it sees. A malicious remote could serve an outdated ring. Members who already hold the newer ring reject it |
| **Signatures are advisory** | Unsigned or unknown-key snapshots are shown (`unsigned`, `?signer`) but not rejected. `author` is a free-form claim; only the signer is authenticated |
| **Embargoes** | See [Embargoes: limitations](embargoes.md#limitations-in-10): metadata stays visible, release time isn't cryptographically enforced, one embargo per line |
| **Concurrent admin edits** | Two admins changing a scope at the same time: the local ring is kept, `vl` warns, and an admin re-applies the missing change |

Next: [Embargoes](embargoes.md).
