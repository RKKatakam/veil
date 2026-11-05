# Secrets and visibility

Every path in a Veil repository has a **visibility tier**, decided by
`.veilpolicy` and by rules built into the engine. The engine enforces it
when it records a snapshot, so no command, merge or push can get around it.

1. [Tiers and `.veilpolicy`](#tiers-and-veilpolicy)
   * [Every file's tier: `vl ls`](#every-files-tier-vl-ls)
2. [Built-in secret rules](#built-in-secret-rules)
3. [The secret scanner](#the-secret-scanner)
4. [Quarantine](#quarantine)
5. [`vl scan` in CI](#vl-scan-in-ci)
6. [The vault: `vl secret` and `vl run`](#the-vault-vl-secret-and-vl-run)
   * [The team vault](#the-team-vault)
7. [Cloaking for a team](#cloaking-for-a-team)
8. [The accepted policy: when an incoming change is held back](#the-accepted-policy-when-an-incoming-change-is-held-back)
9. [What is protected, and what isn't](#what-is-protected-and-what-isnt)

## Tiers and `.veilpolicy`

| Tier | Recorded? | Team remote gets | Public remote gets |
|---|---|---|---|
| `public` (default) | plaintext, **secret-scanned** | it | it |
| `public!` | plaintext, **not** scanned | it | it |
| `cloak [scope]` | encrypted for the scope (default `team`) | ciphertext (members can read it) | nothing: the entry is withheld |
| `isolate` | **never**: local-only, kept in your device's vault | nothing | nothing |
| `ignore` | never, not even locally | nothing | nothing |

`.veilpolicy` is a tracked file at the root of the repository. One rule per
line, **the last matching rule wins**, with one exception, as in Git: a
snapshot never looks inside an ignored directory, so `build/ ignore`
followed by `build/keep.txt public` records nothing below `build/`
(`vl policy check build/keep.txt` says so). Ignore the files instead
(`build/** ignore`) to re-include one of them:

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
$ vl ls
isolated                  20  .env
public                   887  .veilpolicy
public                    12  app.py
cloaked:team              16  secrets/notes.md
```

`vl policy show` lists every rule, built-in ones first.

### Every file's tier: `vl ls`

`vl ls [-r REV] [PATHS…]` lists a snapshot's files (default `@`, the
working copy) with their tier **as you see it**, their size in bytes, and a
note where there is something to say. It never prints content.

```text
$ vl ls --all
isolated                  20  .env
public                   887  .veilpolicy
public                    12  app.py
quarantined               27  cfg.js  (aws-access-key-id; never recorded)
cloaked:team              16  secrets/notes.md
ignored                    -  target/
```

| Tier | Meaning |
|---|---|
| `public` | Plaintext; every remote gets it (also a file of a released embargo) |
| `cloaked:<scope>` | Encrypted for a scope you are in; team remotes get the ciphertext, public remotes nothing |
| `embargoed:<id>` | Under an unreleased embargo whose key you hold |
| `redacted` | Recorded, but you cannot read it: sealed for a scope you are not in, or withheld from your clone. The note says for whom (`(cloaked:ops; no key)`) |
| `isolated` | Local only: never snapshotted, never pushed |
| `quarantined` | Kept out of snapshots: the scanner found a secret in it |
| `ignored` | Not tracked at all (only with `--all`; an ignored directory is listed once, as `target/`) |

The local-only tiers (`isolated`, `quarantined`, `ignored`) come from the
working copy, so they are listed for `-r @` only (and not with
`--no-snapshot`). Paths narrow the list to those files or directories,
relative to the current directory. `vl ls --json` prints the same as one
document ([`veil.ls/1`](../reference/json.md#veills1)).

`vl status` marks changed and local-only files with the same tiers (public
files carry no mark):

```text
$ vl status
Working copy changes:
A .veilpolicy
A app.py
A secrets/notes.md [cloaked:team]
…
Local-only (isolated; never snapshotted or pushed):
  L .env [isolated]
Quarantined (secrets detected; kept local):
  Q cfg.js [quarantined]  (aws-access-key-id; never recorded)
```

`vl files` is the older, plainer listing of recorded files (the label as
recorded, `(redacted)` when unreadable), kept unchanged for scripts that
parse it. Prefer `vl ls`.

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
built-in      .git                     ignore  (dirs and files, any depth)
built-in      .jj                      ignore  (dirs, any depth)
built-in      .hg                      ignore  (dirs, any depth)
built-in      .svn                     ignore  (dirs, any depth)
built-in      .*.sw[a-p]               ignore  (editor scratch files)
built-in      .*.un~                   ignore  (editor scratch files)
built-in      .*.kate-swp              ignore  (editor scratch files)
built-in      *~                       ignore  (editor scratch files)
built-in      #*#                      ignore  (editor scratch files)
built-in      .#*                      ignore  (editor scratch files)
built-in      *___jb_tmp___            ignore  (editor scratch files)
built-in      *___jb_old___            ignore  (editor scratch files)
built-in      .~lock.*#                ignore  (editor scratch files)
built-in      editor and backup artefacts of an isolated, cloaked or ignored file (.x.swp, x~, x.bak, …) take its protection
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
built-in      .npmrc                   isolate
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

The first four keep the metadata of version control systems out of every
snapshot: `.git` (a directory, or the `.git` file of a Git worktree),
`.jj/`, `.hg/` and `.svn/`, at any depth and in any case. No
rule of yours records them, not even `** public` or `vendor/ public!`; only
a `public!` rule that names the directory itself does
(`fixtures/repo/.git/ public!`), for a test fixture that really is a
repository.

`.npmrc` is isolated like `.netrc` and `.pypirc`, because it usually holds
a registry token (`//registry.npmjs.org/:_authToken=…`). A project
`.npmrc` without one (`save-exact=true`, a registry URL, a `${NPM_TOKEN}`
reference) can be shared with your team with `vl cloak .npmrc`, or
published with `vl expose --force .npmrc` (a `public!` rule, which also
turns off secret scanning for it, so keep tokens out of it). A `.npmrc`
recorded before this rule existed stays in earlier snapshots, and the next
snapshot no longer records it.

### Editor swap and backup files

Every `vl` command records the working copy, so a file your editor keeps
next to the one you have open would be recorded too. The next nine rules
keep editor scratch files out: Vim's and nano's swap files (`.x.swp`,
`.x.swo`, …), Vim undo files (`.x.un~`), Kate's `.x.kate-swp`, backups
(`x~`, `x.~1~`), Emacs's `#x#` and `.#x`, JetBrains's `x___jb_tmp___` /
`x___jb_old___` and LibreOffice's `.~lock.x#`. Only an `isolate` rule, or a
`public!` rule that names such files itself (`*~ public!`), changes that.

**Protection follows the name.** A swap, backup or lock file of a
protected file, or a backup copy (`x.orig`, `x.rej`, `x.bak`, `x.backup`,
`x.old`, `x.tmp`, `x.temp`, `x.save`, `x.sav`, also numbered), takes that
file's protection, whatever your rules say about the copy:

| The file | Its artefacts (`.x.swp`, `x~`, `x.bak`, …) |
|---|---|
| isolated (`.env`, `id_ed25519`, `vl isolate`) | isolated: local-only, `L` in `vl status` |
| cloaked under `S` | cloaked under `S` (scratch files stay ignored) |
| ignored | ignored |
| public | scratch files ignored; `x.bak` & co. are ordinary files |

```text
$ vl status
…
Local-only (isolated; never snapshotted or pushed):
  L deploy/.id_ed25519.swp
  L deploy/id_ed25519
$ vl policy check deploy/.id_ed25519.swp
deploy/.id_ed25519.swp: isolated via built-in secret rule 'id_ed25519' (an editor or backup artefact of deploy/id_ed25519, so it has that file's protection)
```

Copies under another name (`cp .env env-old`) are not recognised: isolate
them yourself.

A plain `public` rule on a built-in secret is ignored, and every command
warns until you remove it or settle it with a later `public!`
(`vl expose --force`):

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
| `generic-secret-assignment` | `password = …`, `API_KEY=…`, `JWT_SECRET: …`, `client_secret`, `APP_KEY`, `RAILS_MASTER_KEY`, `<password>…</password>` and similar, with a credential-looking value; camelCase and PascalCase keys in JSON, YAML and JS/TS objects and properties (`githubToken: …`, `"stripeSecret": …`, `this.accessKey = …`, `apiKeyProd`, `apiKey: string = "…"`, `` const authToken = `…` ``); `*_KEY` names (`STRIPE_API_KEY`, `MINIO_ACCESS_KEY`, `SIDEKIQ_LICENSE_KEY`, and any `<WORD>_KEY` or `<word>Key` whose value is a random 16+ characters, such as `MAPBOX_KEY`, `stripeKey`); `DB_PWD`, `Pwd=` in connection strings; XML attributes on any element (`password="…"`, `secret="…"`, `apiKey="…"`, `connectionString="…;Password=…"`), `<add key="DbPassword" value="…"/>`, `<entry key="db.password">…</entry>`, Spring and .NET `<value>` elements; dotted keys of configuration lines and XML entries (`stripe.api.key=…`, `<entry key="api.key">`); `.npmrc` tokens (`//registry.npmjs.org/:_authToken=…`) and credentials in URL query strings (`?apiKey=…&`); also `define('DB_PASSWORD', '…')`, `env["API_KEY"] = …`, Rust/Python typed constants (`API_KEY: &str = "…"`), Kubernetes `name:`/`value:` pairs, Dockerfile `ENV`, plist entries, SQL `WITH PASSWORD '…'` / `IDENTIFIED BY '…'`, Google app passwords |
| `scan-limit` | input crafted against the scanner (it would take far longer than ordinary text): reported rather than scanned to the end |
| `injected-isolated-secret` | the value of an isolated file copied into a `ws exec` sandbox (see [Workspaces](workspaces-and-agents.md#with-isolated)) |

The assignment rule tries hard not to fire on code: references (`$X`,
`${X}`), placeholders (`<key>`), words (`settings.SECRET_KEY`), code
(`os.getenv("PW")`, `lookup(user)`, `self.users[name]`, `[token]`, a
type annotation such as `ENCRYPTION_KEY: KeyFlags = 2`), JSON objects
(`"password":{"type":"string"}`), hashes and encrypted values (`$2b$…`, `ENC(…)`,
`{cipher}…`) and non-credentials (`password_hash`, `token_url`,
`csrf_token`, `nextPageToken`, `tokenizer`, `passwordField`, `PRIMARY_KEY`,
`cacheKey`, `PUBLIC_KEY`, `KEY_PREFIX`) don't count. The camelCase and
`<WORD>_KEY` rules ask more of a value: a quoted literal or one token on its
key's line, not code, not made of words (`BCryptGenerateKeyFn`), not a
UUID. (A camelCase spelling of an older keyword, such as `dbPassword`,
`apiKey` or `_authToken`, may also have an unquoted token in code: a URL's
query string, `.npmrc`, a keyword argument.) A dotted key (`api.key`)
counts only where it starts a configuration line or names an XML entry,
not in code (`obj.key = …`). A random password is found whatever symbols it has, including `$`,
`%`, quotes and brackets.

**Known misses** (see [`docs/BACKLOG.md`](../BACKLOG.md)): word-only
passphrases and passwords with spaces, weak passwords, URL passwords that
are words or numbers, keys not on the keyword list (`credentials`,
`pass`), values whose key is on another line (except Kubernetes `value:` and XML
elements), unquoted values in code under camelCase keys that only scanner
v6 knows (`githubToken`, `stripeKey`), values more than
16 KiB of blanks after their key, values longer than 256 characters are
judged on their first 256, and compressed archives (`.zip`, `.tar.gz`,
`.docx`, `.jar`), which are not decompressed. About 1 random 16-character
password in 3,000–5,000 is still taken for a word, hash or code; under a
camelCase or `<WORD>_KEY` key, about 1 in 300–1,000 at 16 characters (1 in
1,000 at 20; 1 in 100 if only upper-case letters and digits). The scanner is
a safety net, not a guarantee: keep real secrets in isolated files or the
vault.

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
  L .env [isolated]
Quarantined (secrets detected; kept local):
  Q cfg.js [quarantined]  (aws-access-key-id; never recorded)
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

### As a CI gate: `--policy-from`

In CI, do **not** take the rules from the checkout you are scanning: the
pull request that adds a leaked key can add `leak.js public!` (or
`** public!`, or `leak.js cloak`) to its `.veilpolicy` in the same commit.
`vl scan --policy-from FILE` takes its rules from FILE, a policy the pull
request cannot edit (the base branch's), and disregards the checkout's
own `.veilpolicy`. It needs no Veil repository (no `vl init`, no identity)
and changes nothing on disk.

A CI checkout publishes every file in it, whatever a policy says, so in
this mode every file counts as public: only FILE's `public!` paths (your
reviewed test fixtures) are exempt. `isolate`, `cloak` and `ignore` paths
are scanned too; only `.git/` (and other VCS metadata) is skipped. A file
that cannot be read fails the gate.

```sh
# The base's policy (an empty file means the built-in rules only).
vl scan --policy-from "$RUNNER_TEMP/base.veilpolicy"
```

```text
PUBLIC    leak.js:1  aws-access-key-id AKIA…(20 chars)
found: 1 file(s) contain secrets (or could not be scanned); only the `public!` paths of base.veilpolicy may
```

In a CI step this fails the job on a hit (exit 1; a missing FILE is an
error and fails it too). For pushes to a protected branch, whose
`.veilpolicy` was reviewed when it merged, `--policy-from .veilpolicy`
works the same way.

Plain `vl scan` (no `--policy-from`) applies the working copy's own
policy, guarded by the policy you accepted on this device: right for your
own working copy, not for a gate.

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
| `vl secret files` | List the vault's backups of isolated files, including those of files gone from the working copy (kept 30 days) |
| `vl secret recover PATH` | Write the backup of an isolated file back into the working copy (never over an existing file) |
| `vl run -- CMD…` | Run `CMD` with the vault's secrets in its environment (and those of the team vaults you choose, see below); exits with its status |

The vault is per repository and per device. A teammate's clone has its own.
Replacing your identity makes the vault unreadable until you re-key it
(`vl identity recover-vault`, see [Maintenance](maintenance.md#replacing-your-identity)).

### The team vault

Secrets the whole team needs (a staging database URL, a shared API key) go
into a scope's **team vault**: sealed for the members of the scope and
synced through team remotes, so a new teammate who is granted the scope gets
them on their next `vl pull`. Public remotes never receive it.

```text
alice$ vl secret set --scope team STRIPE_TEST_KEY        # value from stdin
Stored secret STRIPE_TEST_KEY in the team vault of scope team; push to share it with its members
alice$ vl push
bob$ vl pull
bob$ vl secret list --scope team
STRIPE_TEST_KEY  set by alice 2026-11-04 14:53:28 (key generation 0)
bob$ vl run --scope team --remember -- npm test   # STRIPE_TEST_KEY is in its environment
bob$ vl run -- npm test                # from now on, on this device
```

| Command | Does |
|---|---|
| `vl secret set --scope S NAME [VALUE]` | Store (or overwrite) a secret in scope `S`'s team vault. You must be a member, granted with your full public key |
| `vl secret get --scope S NAME` | Print its value to stdout |
| `vl secret list --scope S` | List names, with who last set each and when; never values |
| `vl secret list --scope S --exposed-to MEMBER` | Only the names MEMBER (public key, member id or name; current or revoked) could read |
| `vl secret rm --scope S NAME` | Delete it (a signed deletion that syncs like a write) |
| `vl secret list --scope S --json` | The same as a [`veil.secret.list/1`](../reference/json.md#veilsecretlist1) document (names, who, when, key generation) |
| `vl run [--scope S]… [--local-only] -- CMD…` | Choose which team vaults `vl run` loads |
| `vl run --scope S… --remember [-- CMD…]` | Make those scopes this device's default (`--local-only --remember`: none) |

Names are letters, digits and `_`, starting with a letter or `_` (shell
identifiers), because they become environment variables. Values are at
most 64 KiB, and a scope's entries at most 256 KiB in all: a command's
arguments and environment together are limited to about 1 MiB (macOS) or 2
MiB (Linux), so a bigger vault would break everyone's `vl run`. Keep
certificates and key files as cloaked files instead.

**What `vl run` loads, in order.** The team vaults of the scopes you name
with `--scope S` (repeatable), or, without `--scope`, the scopes you chose
on this device with `--remember`, then your local vault on top: a local
secret with the same name overrides the team's (handy for a personal
override of a shared value), and both override variables already in the
environment. Until you choose, `vl run` loads no team vault and says which
scopes hold secrets. `--local-only` loads none. If two loaded scopes set the
same name to different values, `vl run` refuses and names both, rather than
pick one; choose with `--scope`, or set the name in your local vault.

Every member of a loaded scope chooses what its entries are, and your
command sees them next to the secrets of every other loaded scope and of
your local vault. That is why nothing is loaded until you choose, and why
you should remember only scopes whose members you trust with each other's
secrets: use `--scope` when a command should see less, for example to keep
`prod` secrets out of a test run.

**Variables a team vault never sets.** Names that decide what a command
runs, loads or trusts are never taken from a team vault, whatever the
scope: `PATH`, `LD_*`, `DYLD_*`, `BASH_ENV`, `ENV`, `PROMPT_COMMAND`,
`SHELL`, `IFS`, `HOME`, `TMPDIR`, `NODE_OPTIONS`, `PYTHON*`, `PERL*`,
`RUBY*`, `JAVA_TOOL_OPTIONS`, `GIT_*`, `NPM_CONFIG_*`, `XDG_*`, `VEIL_*`,
compiler and build flags, proxies and CA bundles, and the configuration
paths of common tools (`KUBECONFIG`, `DOCKER_HOST`, `AWS_CONFIG_FILE`, …);
the full list is `EXECUTION_VARIABLES` in `crates/veil-core/src/team_vault.rs`.
Otherwise any member could run code of their choosing in every teammate's
`vl run`. `vl secret set --scope` stores such a name but warns, and `vl run`
skips it with a warning. If you trust a value, copy it into your local
vault: `vl secret get --scope team NAME | vl secret set NAME`.

**Who can read and write.**

* Every entry, **name and value**, is encrypted under the scope's current
  key, so the operator of a team remote sees only opaque record ids, sizes
  rounded to 128 bytes, write times and who wrote.
* Every write is signed by its author. An entry counts only if its author is
  a **current** member of the scope, signing with the key the scope's ring
  registers for them. A write by someone else, by a revoked member, or with
  a bad signature is ignored, and `vl pull` warns about it.
* Members granted with the short member id can read but not write.

**Concurrent writes.** For each name the newest signed write wins, and a
deletion is a write. A write is stamped later than everything its author had
pulled, so a write you make after pulling always wins over what you saw,
whatever the clocks say. Two teammates writing the same name without
pulling each other's write: the later timestamp wins, the same on every
replica. Records stamped more than a day ahead of your clock are refused,
and both `vl push` and `vl pull` say so. If your clock was wrong when you
wrote a secret, your next write of it replaces that record (on the remote
too, at the next push) instead of being stamped after it.

**Key rotation.** After `vl scope rotate` (or a revocation) new writes are
sealed under the new key. Existing entries stay readable through the key
chain, and move to the new key the next time someone writes them.

**When someone leaves.** `vl scope revoke` lists every team-vault secret
the revoked member could read, the secrets to rotate:

```text
alice$ vl scope revoke team veil1e75c0889…c00a
Revoked. Scope team rotated to key generation 1: …
Team vault of scope team: the revoked identity could read 2 secret(s). Rotate each at its source,
then store the new value with `vl secret set --scope team <name>`:
  DB_PASSWORD
  WEBHOOK_SECRET
Their writes no longer count, so you re-signed the 1 secret(s) they last set (still to rotate): WEBHOOK_SECRET
```

Their writes stop counting from the revocation on. Entries whose current
value they wrote are re-signed by you, so the team keeps working until you
rotate them. `vl secret list --scope team --exposed-to <their key or name>`
shows what is still left to rotate: a name drops off the list once it holds
a value set after the revocation. Setting the *same* value again doesn't
count as rotation, nor does going back to a value they could read (after a
rotation that broke something, or a deletion): vl remembers, on each
device, which values each name held.

**Teammates who have not pulled the revocation.** `vl secret set --scope`
first brings the scope's key ring up to date from your team remotes, so a
new value is sealed with a key the revoked member never gets; if no team
remote answers, it warns. `vl push` re-seals your own values sealed with an
older key than the remote's before sending them. If a value sealed with an
old key after a revocation reaches you anyway (from an older vl, say), `vl
pull` names it and `vl secret list --scope` marks it "sealed under an old
key generation after a revocation": set it again, and rotate it.

**Undo.** Team-vault writes are not part of the operation log (like key
rings). `vl undo` refuses them and tells you how to reverse the write by hand
(`vl secret rm --scope …`, or set the old value again). Once pushed,
teammates have the value.

## Cloaking for a team

A **scope** is a named group of identities that share a key. `vl init`
creates `team`, with you as its admin. A cloaked file is encrypted for its
scope's current key; only members can read it, and public remotes never
receive it.

```text
$ vl scope list
team  admin  generation 0, 1 changes
    alice        admin  veil15dc25eaf4116d32ea46c6bc1cc0f2a62f04e962ecb4c585f4f827bd609b96d59 (you)
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
$ vl scope revoke team veil1e75c…0a
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
that public remotes never receive. Both need a scope you are a member of
(`local` and `embargo/…` are not scopes).

**Visibility never widens by accident.** Rebase, `vl new`, squash, and
policy edits that arrive by merge keep sealed files sealed. Publishing is
explicit: `vl merge` of a cloaked line (secret-scanned; it lists what it
published) or `vl expose`. That merge publishes only what the line brings
in (not what your destination already holds sealed), and only if every
snapshot it brings in is signed by a current member of the line's scope.
Otherwise it warns, and the files stay cloaked: a teammate outside the
scope can copy your sealed files into a snapshot that claims to be a
`team` line, but cannot sign as a member.

**Content never moves between scopes by merging.** When the two sides of
a merge, rebase or auto-rebase hold a file sealed for different scopes
(say `team` and `ops`), `vl` does not seal the combined content for
either: the file is a conflict, and the side that kept the scope it had
before (else the destination's) is kept as it is. Reconcile them
deliberately (`vl cloak --scope`).

**Editing does not either.** If `.veilpolicy` cloaks a file under `team`
but the version you checked out is sealed for another scope, say `mal`
(someone who can push replaced it; an honest re-key edits the policy at
the same time), your edit is sealed for neither. It stays local and every
snapshot says so; history keeps the recorded version. Look at what
changed the file, then decide: `vl cloak --scope team PATH` seals your
edit for `team`. If the policy you checked out re-keys the file and your
accepted policy holds that back, the report points to `vl policy accept`
instead.

A conflict keeps every version as it was sealed: a conflict between a
public version and one sealed for `team` names both, and a public remote
receives the public version and the conflict, never the sealed one. The
markers are written only into your working copy, for you. A version sealed
for an audience the file with markers does not have is never shown in it:
the base (the `||||||| original` section) is left out when it was sealed
for an audience the merged file does not have (say it was cloaked for
`team` and both sides made the file public), and a side you cannot read is
a `(not shown: …)` line. A public reader sees public versions, and a
`(not shown: this version is not public)` line for every other one. The
file with markers is
sealed like a merged file (never wider than a side it shows), so a
resolution is sealed the same way.

> **Public files edited in a cloaked workspace.** A public file you *edit*
> in a cloaked workspace is recorded cloaked, together with its last public
> version. Anyone who cannot read the scope (a public remote, teammates
> outside it) keeps seeing that last public version, never a
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
warning: 1 local path(s) keep the protection you accepted: .veilpolicy would weaken it, and that change came from a merge, pull, checkout, restore or undo (or a symlinked policy file) rather than your own edit (.env (isolate → public!)). Review it with `vl policy show`; apply it with `vl policy accept`

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
by: merge, pull, checkout (`vl new`, `vl edit`, `vl ws switch`), rebase,
`vl restore [--from REV]`, undo and `vl op restore`. Only your
own edit of the file (by hand, or with `vl cloak|isolate|expose|ignore`)
applies at once; putting back another revision's policy with `vl restore`
is not your edit. In colocated Git mode, where Git may write the file at
any time, a hand edit counts as yours only if Git cannot have written it
(see [Colocated Git mode](colocated-git.md#your-edits-of-veilpolicy));
`vl cloak` and friends always do.

**The policy file itself never lowers protection** below the policy you
accepted:

* **Deleted:** your accepted policy still applies, and every command says
  `.veilpolicy is missing`. `vl restore .veilpolicy` brings it back;
  `vl policy accept` accepts having none.
* **A symlink** (dotfiles managers, `stow`, a monorepo's shared policy):
  Veil applies the rules of the file it points to (if its name says it is
  a policy file: `.veilpolicy`, `dot_veilpolicy`, `team.veilpolicy`), but a change there is
  never taken as your edit (it can come from a sync or a pull Veil does not
  see): new protection applies at once, anything weaker waits for
  `vl policy accept`. History keeps the recorded `.veilpolicy`, so
  teammates do not get changes made through the link; replace it with a
  copy to share them. `vl cloak` and friends refuse to write over the link.
* **Unreadable, a directory, a dangling or looping link:** your accepted
  policy applies as it is, every command warns `cannot read .veilpolicy`,
  and `vl policy accept` refuses until you fix it.

**Agents can't declassify either.** In a `vl ws exec` sandbox or a
`vl ws mount`, the command (an agent, a tool) edits `.veilpolicy`, not
you. An edit there that weakens the workspace's policy is held back the
same way, against the workspace's recorded policy, until you run
`vl policy accept --workspace NAME`
([details](workspaces-and-agents.md)).

## What is protected, and what isn't

The full threat model is in
[`docs/ARCHITECTURE.md`](../ARCHITECTURE.md#threat-model), and open issues
are in [`docs/BACKLOG.md`](../BACKLOG.md). In short:

**Protected:**

* Accidental commits of secrets: the built-in rules, the scanner and
  quarantine, with no ignore file to forget.
* Cloaked content, cloaked descriptions and cloaked tags never reach public
  remotes. Readers of a team remote who are not in the scope get
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
| **Scope membership is visible on team remotes** | Key rings go to team remotes, so anyone who can read one can list each scope's member names and ids (`vl scope list`). Public remotes get no rings; a public mirror shows only the member ids and signing keys in the signatures of what it holds (snapshots, embargo records) |
| **Equality leakage** | Sealing is deterministic: two cloaked files (or versions) with identical content produce identical ciphertext, so an observer can tell they are equal |
| **Revocation is forward-only** | A revoked member keeps every key up to the revocation, so they can still read all history sealed before it, including unchanged files still sealed under an old generation, and anything they already decrypted. Rotate the underlying secrets |
| **Plaintext history stays** | Cloaking a path doesn't encrypt earlier snapshots |
| **Trust on first use** | A fresh clone accepts the first valid key ring it sees. A malicious remote could serve an outdated ring. Members who already hold the newer ring reject it |
| **Signatures are advisory** | Unsigned or unknown-key snapshots are shown (`unsigned`, `?signer`) but not rejected. `author` is a free-form claim; only the signer is authenticated |
| **Embargoes** | See [Embargoes: limitations](embargoes.md#limitations-in-10): metadata stays visible, release time isn't cryptographically enforced, one embargo per line |
| **Team vault metadata** | A team remote's operator can't read names or values, but sees how many entries a scope has (roughly), their sizes in 128-byte steps, when they were written and by whom. They can also withhold records: a fresh clone then sees an older value, or a deleted secret (members who already pulled the newer record keep it) |
| **Concurrent admin edits** | Two admins changing a scope at the same time: the local ring is kept, `vl` warns, and an admin re-applies the missing change |

Next: [Embargoes](embargoes.md).
