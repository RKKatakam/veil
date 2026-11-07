# The Veil server

**Veil is server-centric** ([OVERVIEW.md](../OVERVIEW.md)): the server holds
every project and decides who sees what ([VISIBILITY.md](../VISIBILITY.md)).
This page covers milestone S1: signing in, projects, groups, folder access,
secrets, and pushing and pulling through the server. The server's design and
every decision it made are in [HUB.md](../HUB.md) §13.

1. [Running a server](#running-a-server)
2. [Signing in](#signing-in)
3. [A project: you are its admin](#a-project-you-are-its-admin)
4. [Groups and folder access](#groups-and-folder-access)
5. [Cloning, pulling and pushing](#cloning-pulling-and-pushing)
6. [Secrets](#secrets)
7. [What someone without access sees](#what-someone-without-access-sees)

## Running a server

The server is `veil-server` (`crates/veil-server`). It needs PostgreSQL (or
YugabyteDB) and a directory or an S3 bucket for objects:

```sh
veil-server --database-url postgres://veil:veil@127.0.0.1:5432/veil --data ./hub --listen 127.0.0.1:8443
```

Without `--tls-cert` and `--tls-key` it makes a self-signed certificate for
`localhost` and `127.0.0.1`, at `./hub/self-signed-cert.pem`; give that file
to `vl login --ca` once. Objects go to `./hub/objects`, or to S3 with
`--s3-endpoint URL --s3-bucket NAME` (credentials in `VEIL_S3_ACCESS_KEY` and
`VEIL_S3_SECRET_KEY`).

## Signing in

Your device signs in with its identity key (the one `vl identity show`
prints); nothing to type but your name, the first time:

```text
$ vl login veil://127.0.0.1:8443 --name alice --ca hub/self-signed-cert.pem
Signed in to 127.0.0.1:8443 as alice
  this device 4F2A-9C1E-77B0-D3E5-A1C2
  server key  d0fca5e69d6afaf0343dbc7728611ac7588abe1ca3d2e82e98969059caae08cf
```

The session lasts hours; when it ends, `vl` signs in again with the key,
without asking. The session token is kept in `$VEIL_HOME/hub.json`, readable
only by you. Your private keys never leave the device.

**This device** is your device's fingerprint (`vl identity show` prints it
too). Your first device is confirmed once, with an invite link (below) or by
an admin comparing this fingerprint with you, before it receives secret keys.

**Another device of yours** signs in with the same command and name. It
waits until you confirm it from a device you already use, then signs in.
Run the confirmation in a clone of a project, and that device shares the
project's secret keys with the new one at once:

```sh
vl identity confirm 7C1B-0E44-93AD-2F18-B6C0    # on your laptop: the new device's fingerprint
```

Nobody else can stop this by making up devices under your name: the new
device is looked up by its fingerprint, and it waits for a day. (If strangers
flood your name with so many devices that yours was pushed out, `vl identity
confirm` says so: sign in on the new device again and confirm it; from then
on nobody can push it out.)

**Each project's fingerprint.** A device trusts a project's secret keys only
once it knows the project's fingerprint, so a hacked server can never hand it
another project's keys, or keys of its own making. An invite link carries the
fingerprint, so `vl join` needs nothing more. Otherwise (a new laptop of
yours, or an admin who confirmed your device with `--confirm`), your first
`vl clone` of the project shows the fingerprint the server claims and opens no
secrets yet. Compare it with `vl identity show` in a clone on another of your
devices (it prints `project  9D3E-…`), or with your admin, then confirm it in
the clone:

```sh
vl identity confirm 9D3E-51A0-C7F2-0B64-E18D    # in the clone: the project's fingerprint
```

Every later clone of the project on this device trusts the same keys.

**A lost laptop:** remove it from another of your devices, in a clone of the
project. It can no longer sign in anywhere, and the keys of every secret it
could open rotate away from it (it keeps what it already had). An admin can
remove anyone's device **from their own project**: it can no longer use that
project, and the project's keys rotate away from it, but only its person can
remove it everywhere.

```sh
vl identity remove 7C1B-0E44-93AD-2F18-B6C0
```

## A project: you are its admin

Point a repository at a project on the server and push. Pushing to a project
that does not exist creates it, with you as its admin, and **everything
private**:

```text
$ vl remote add origin veil://127.0.0.1:8443/acme
$ vl tag set main -r @-
$ vl push
Created project acme on 127.0.0.1:8443: you are its admin, and everything is private
  pushed main → cd19a309
Sent 8 object(s) to origin
```

## Groups and folder access

Admins create groups, add people, and choose managers; a group's managers
add and remove other people in it, never themselves:

```sh
vl group create finance
vl invite alice --to finance       # someone new, or a remote teammate
vl group add finance bob           # someone whose device is confirmed already
vl group manager finance carol
vl group list
```

**An invite** is the easy way to bring someone in:

```text
$ vl invite alice --to finance
Invited alice to finance in acme. Send them this link (Slack, email):

  veil://127.0.0.1:8443/acme#invite=alice:5f2c…:9D3E51A0…

  They run `vl join -` and paste it (on a shared machine, never put it on the command line).
  It works once, for 7 days. The server never sees the secret in it: their device's keys for billing/ come from it.
```

Alice runs `vl join -` and pastes the link (or `vl join LINK`; on a machine
other people use, the link on the command line can be read by them while it
runs). It signs her device in (registering the name `alice` if it is new),
joins her to `finance`, and confirms her device: the next teammate's device
that runs `vl` gives it the keys of `finance`'s folders. The link holds a
secret that never reaches the server, so a hacked server cannot use it to
slip in a device of its own, and the project's fingerprint, which `vl join`
checks: if the server's keys for the project are not those, it says so and her
device trusts none of them. If someone else uses a leaked link first, alice's
`vl join` says it was used: remove that device (`vl identity remove`) and
invite her again.

Without an invite, an admin's `vl group add` shows `confirm alice's device:
4F2A-…` for a device nothing confirms yet; compare it with what `vl identity
show` prints on alice's device, then run `vl group add finance alice --confirm
4F2A-9C1E-77B0-D3E5-A1C2` (one person at a time). Give alice the project's
fingerprint at the same time (`vl group add` prints it): she confirms it in
her clone (`vl identity confirm 9D3E-…`), as above.

Access is written in `.veilpolicy`, one line per folder, **the last matching
line winning**:

```text
src/          public devs
billing/      finance
infra/        ops carol
```

- A folder (or file) from the project root, then who may see it: groups,
  people, or `public`.
- **Folder access means read and write.** `public` means everyone on Earth
  may *read*; writing a public folder needs a named group or person (here
  `devs`).
- A path no line covers is private: only admins see it.
- `vl access PATH WHO…` writes the line for you (replacing the line for the
  same path), and `vl access PATH` asks the server who can see a path and
  which line decides:

```text
$ vl access billing/ finance
Added to .veilpolicy: billing/                finance
  Push it to apply (only admins may change access; the last matching line wins).
$ vl access billing/
billing  decided by `billing/` (.veilpolicy line 21)
  groups  finance
  admins  admin1
  you     read and write
```

**Only admins change access.** The server refuses a push that changes an
access line unless an admin made it, on any branch. What counts is the policy
accepted on the default branch (`main`), never what a snapshot claims.
When an admin's push changes access, the server lists exactly who can now
see what.

## Cloning, pulling and pushing

```sh
vl clone veil://127.0.0.1:8443/acme
vl clone veil://127.0.0.1:8443/acme acme-billing --only billing
vl pull
vl push
```

- **You receive only what you may see.** Folders you cannot see are not in
  your clone at all: no files, no names, no history of changes that touched
  only them.
- `--only DIR` fetches one directory: the server sends only that
  directory's objects (and the folders on the way to it). The rest stays on
  the server and is kept unchanged by your commits.
- **Pushing** checks every path you changed: writing to a folder you may not
  write, or creating a file where nobody gave you access, is refused. Moving
  a branch is a compare-and-swap: if someone moved it first, `vl` tells you
  to pull. Forcing a branch back, or deleting one, needs an admin.
- Snapshots you receive are signed: by their author, or, where the server
  left out something you cannot see, by the server's key (`vl log` shows
  `?signer` for it).
- **The server scans what it receives for secrets**, as `vl` does before
  it records a file: a token or password in an ordinary file is refused,
  and the message names the file, the rule and the line, never the secret.
  Only an admin's `public!` line (test data) turns this off for a folder.

## Landing changes, and protected branches

On a busy branch, many people and agents land at once. `vl land` hands a
change to the server's **landing service**, which puts it on the newest tip
for you:

```sh
vl commit -m "Fix the parser"
vl land                       # @- onto the default branch; waits for the outcome
vl land xoruqyku --onto release   # another change (by its id), another branch
vl land --no-wait             # prints a ticket at once
vl land --status land-4f2a…   # its outcome later
```

- **You need not pull first.** The change lands on the branch's newest tip
  if no path it edits changed there since the snapshot you made it on. The
  check is exact, path by path: whatever else moved does not matter.
- **Each change keeps its own snapshot**, one after another, but the server
  moves the branch once for many changes landing together.
- **Outcomes:** `landed` (your local tag follows the change to where it
  landed), `conflict` (it names the paths that changed meanwhile: pull,
  redo the change on the new tip and land again), or `rejected` (a check
  refused it; the message says which).
- **The same checks as a push**, when you submit, and again when it lands
  if your access changed meanwhile: someone removed from a group, or an
  access change landed first, is refused at that point.
- A change that edits `.veilpolicy` or `.veilrules` lands alone, and the
  changes after it are checked against the new rules.

**Protected branches** move only through the landing service. An admin
protects one in a `.veilrules` file at the project root:

```toml
[branches.main]
protected = true
```

- `vl push` to a protected branch **lands your new changes instead**: a
  one-person project notices nothing, and a team never races to push.
- A commit through the API with `--onto` a protected branch is kept but
  does not move it: land it instead.
- Only admins change `.veilrules`, on any branch. An admin's
  `vl push --force` still moves a protected branch (it is recorded).
- Over HTTPS: `POST /v1/projects/{project}/land` and
  `GET /v1/projects/{project}/land/{ticket}` ([HUB.md §13.15](../HUB.md)).

## Committing without a checkout

Scripts, CI jobs and agents can make a change with no clone at all: send
the server a list of edits on top of a revision, and it builds the change
on its own copy of the project.

```sh
cat > edits.json <<'JSON'
[ {"path": "src/version.txt", "put": {"text": "1.4.2\n"}},
  {"path": "src/old.rs", "delete": true} ]
JSON
vl change new veil://127.0.0.1:8443/acme --edits edits.json -m "Bump the version" --onto main
```

- **Every check a push gets applies:** you write only the folders you may
  write, only admins change access lines, personal keys are refused,
  secret files only go up encrypted, and the server scans for secrets.
- **`--onto main`** moves `main` to the change in the same request. If
  `main` moved since the revision you started from, the server applies your
  edits to its new tip itself, unless a file you edit changed there (then
  `vl` says so; the change is kept, and you can make a new revision of it
  on the new tip with `--change ID`). `--expected ID` moves `main` only if
  its tip is still that snapshot.
- **Without `--onto`** the change is kept on the server under its change
  id, and can be the `--base` of the next one.
- **Secret files** (`.env`) must be encrypted before they leave your
  device: run `vl change new` in a clone of the project, which holds their
  key. Outside a clone it refuses to send them. It also scans every other
  file itself first, so a secret never leaves your machine.
- The edits are paths from the project root, at most 10,000 per change and
  64 MiB of text. The change's author is you; the server signs it.
- The same thing over HTTPS is `POST /v1/projects/{project}/changes`
  ([HUB.md §13.13](../HUB.md)).

## Secrets

- **New repositories encrypt shared secrets** (`.env`, `.env.*`, `.envrc`,
  Terraform state) on your device and sync them; the policy `vl init` writes
  says so (`cloak rule`).
- **Each folder's secrets have their own key**, held by whoever may see the
  folder, and by the admins: `finance` opens `billing/.env`, and nothing that
  opens `infra/.env`. A secret no access line gives anyone is the admins'.
  `vl access` sets up the folder's key.
- **Personal private keys and credentials** (`id_rsa`, `id_ed25519`,
  `*.pem`, `*.key`, `.netrc`, …) never leave your device; the server refuses
  them.
- **Keys reach confirmed devices only, on their own.** A device is confirmed
  by an invite, by an admin's `--confirm`, or by its person from another of
  their devices. Teammates' devices that hold a key share it with confirmed
  devices in the background, within seconds of running any `vl` command (set
  `VEIL_KEY_SHARE=0` to turn that off on a device). The key ring checks every
  share: a server that lists a device of its own under your name gets
  nothing, whatever it claims.
- **Removing someone rotates only the keys they lose**: leaving `finance`
  rotates `billing/`'s key away from all their devices, even ones the server
  hides; if another group still gives them the folder, the removal says so.
  A manager's addition gives the folder but not the key, and a manager's
  removal asks an admin to rotate it.
- **An existing repository** starts syncing its secrets only when you ask,
  after seeing the list:

```sh
vl upgrade --sync-secrets --dry-run
vl upgrade --sync-secrets
```

- **A project from before keys per folder** (one key for every secret) moves
  only when an admin asks: it lists every secret with its new key and who
  will hold it, and the old key becomes the admins' only. Then commit and
  push; everyone else runs `vl pull`, then `vl policy accept`.

```sh
vl upgrade --rule-keys --dry-run
vl upgrade --rule-keys
```

## What someone without access sees

Bob is not in `finance`. His clone of `acme` has `src/` only: no `billing/`,
not even its name, and no trace of changes that touched only `billing/`. Anyone
on Earth, not signed in, gets the `public` folders the same way; a project with
nothing public does not exist for them.
