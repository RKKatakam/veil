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

Its limits have defaults (`docs/HUB.md` §13.25): `--device-rate 200/50000`
(a burst a second, the most an hour), `--anonymous-rate 20/1000` per address,
`--max-connections 1024` and `--request-memory 512M` (all request bodies
held at once, and as many of answers being written).

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
vl clone veil://127.0.0.1:8443/acme                       # thin: the tips and what it checks out
vl clone veil://127.0.0.1:8443/acme --full                # every snapshot and file you may see
vl clone veil://127.0.0.1:8443/acme acme-billing --only billing
vl pull
vl push
```

### Thin clones

`vl clone` is **thin** by default: it fetches the branch tips and the
files of the branch it checks out (`main`), and nothing of the history
below. Everything else comes from the server the first time something
reads it: `vl show` of an old change, `vl diff` against one, moving the
working copy to another revision. `vl log` shows the whole history, page
by page from the server, and keeps what it fetched. Status, commits and
pushes work as in a full clone, and a large project clones in seconds.

- **Always connected.** A thin clone has no offline mode: a command that
  needs something it has not fetched, while the server cannot be reached,
  fails and says so (`the Veil server could not be reached: …`) before it
  changes anything. Nothing is ever shown as hidden because it was not
  fetched. What you already have keeps working: `vl status`, `vl commit`,
  `vl diff` of your own changes.
- **A bounded cache.** Fetched files and folders are kept in `.veil/cache/`,
  at most 4 GiB by default (`vl clone --cache-size 8G`, or later `vl partial
  limit 8G`). The oldest are evicted when it fills; what your working copies
  hold, and everything you made yourself, never are. A checkout larger than
  the cache is refused with a message, never evicted in a loop.
- **You still receive only what you may see**, file by file: the clone asks
  only for what it met in the folders the server gave it, and the server
  checks every request.
- `vl partial status` shows the cache and what is pinned; `vl partial full`
  fetches everything and makes the clone a full one (format 8).
- A thin clone is repository format 9: a `vl` older than this one refuses
  it rather than misreading it. `--only` clones are not thin (they keep
  every snapshot, and only their directory's files).

### The Veil daemon: one cache for the whole machine

Every thin clone and workspace on your machine shares one object cache,
kept by a small background process, the **Veil daemon**. `vl` starts it
the first time a thin clone needs something. Once one clone or agent
has read a file, the others on the machine read it from the daemon, not
the server (agents that ask for the same new file at the same moment
each fetch it: those first reads are not combined), and a new clone finds
the project's top folders already there (the daemon keeps the top
folders of `main` of the projects you use up to date).

```text
vl daemon status                 its cache, what it served, the servers it reads from
vl daemon stop                   stop it and keep it off: vl reads from the server directly
vl daemon start [--cache-size 8G]  turn it on again (default size: 20 GiB or a tenth of the disk)
```

- **It never gives anyone more than the server would.** It holds no key
  and no session. Every read names the server's signed grant for what you
  may see, signed by your device, and the daemon checks both, and that the
  file is inside that grant, before it looks at its cache. Within 5 seconds
  of someone losing access (removed from a group, a folder no longer
  public, a device removed), the daemon stops serving them; if it cannot
  reach the server for 5 seconds it serves nothing from its cache at all.
- **It changes no answer.** Whatever it does not send, `vl` asks the server
  for, and only the server's answer ever means "not there for you". With
  the daemon off, or stopped, or broken, `vl` works exactly as before: a
  daemon that does not answer within half a second, or speaks another
  version, is passed over for the rest of that command.
- **It is yours alone**: its socket and cache are in folders only your OS
  user can open (`$XDG_RUNTIME_DIR/veil/` and `~/.cache/veil/daemon/`, or
  `$VEIL_HOME/daemon/`), and it refuses connections from other users.
  Commands run with `vl ws exec` cannot see either: an `--allow` of a
  folder that holds them (`~/.cache`, `~`) is refused. Secret files are in its
  cache only as ciphertext. People who must not read each other's files
  need separate OS users, as for any file on the machine.
- **It is bounded**: least recently used objects go first when the cache
  is full, except what your working copies check out.

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

### Sharing one secret with one person

Any member can give another member **one of their secret files**, without
an admin: a test API key for a contractor, your `.env` for a teammate
outside your folder.

```sh
vl secret share billing/.env.stripe-test --with bob
#   Shared billing/.env.stripe-test with bob (version 1, 2 devices)
vl secret shares                    # what you share and receive (admins: every share)
vl secret unshare billing/.env.stripe-test --from bob
```

- **Only bob's confirmed devices, and yours, can open it.** It is a copy of
  that one file under a key of its own: bob gets nothing else of `billing/`,
  and the server stores only ciphertext. A device of bob's that no key ring
  records, nobody compared, and no invite or vouch confirms is shown as
  `confirm bob's device: 4F2A-…` and gets nothing; if bob is in no key ring
  at all, compare that fingerprint with what `vl identity show` prints on
  his device and add `--confirm 4F2A-…`.
- **It is a file that is a secret**: `.env`, `.env.*`, `.envrc`, Terraform
  state, or one the project's policy seals. Never code (give folders with
  `vl access`) and never a personal key.
- **Bob's `vl pull` writes it at the same path**, where it stays on his
  device: never recorded, backed up in his local vault, and given to his
  agents with `vl ws exec --with-isolated`. It never writes over a file bob
  changed (nor over a link or anything but a regular file), and not on a
  device that holds the folder's key itself (that device would record it
  for everyone in the folder; if his device gains that key later, the copy
  moves to `.veil/local/secret-shares-held/`).
- **Run `vl secret share` again to send a new version; devices he adds
  receive the current version automatically** (from the clone you shared
  it from, after any `vl` command there). An edit of the file alone sends
  nothing. A device he removes gets no later version. A share that pauses
  or ends on the server is no longer sealed for his new devices until you
  share it again.
- **Admins see that it is shared** (who, which path, when), never what it
  holds. The share pauses while you may no longer read the file's folder,
  or bob no longer takes part in the project.
- **`vl secret unshare` stops later versions; it cannot take back what bob
  already received.** Rotate the secret if that matters.

## Searching

`vl search` asks the server, so it works the same in any clone and needs
no checkout:

```
vl search handler                    # code at the tip of main, best matches first
vl search parse config --lang rust   # every word must occur (any case)
vl search -r feature-x handler       # another branch's tip
vl search invoice --path             # file names, over all of the project's history
vl search handler -- src/api         # only under src/api
vl search handler --json             # the server's answer (veil.search/1)
```

You find only what you may see: a folder you cannot see is never found,
counted or ranked, and a secret file (`.env`) is found by its name, never by
what it holds. A branch just pushed takes a moment to be indexed; `vl
search` waits for it.

## The project's health, and the server's limits

As an admin, `vl stats` shows what the server did for the project since it
started (and over the last minute): requests, how many were refused for
going too fast (`429`) or shed under load (`busy`), cache hits, and how far
the derived history lags. Only the project's admins see it.

```
vl stats
vl stats --json      # the server's answer (veil.health/1)
```

Each device may send a burst of 200 requests a second within 50,000 an
hour (your agents on that device share it); requests without a session
(anyone on Earth, sign-in) 20 a second within 1,000 an hour per address.
Past it the server answers `429` and says when to come back, and `vl` waits
and tries again. One busy project leaves the others room: it runs at most
three quarters of the server's database connections at once.

## What someone without access sees

Bob is not in `finance`. His clone of `acme` has `src/` only: no `billing/`,
not even its name, and no trace of changes that touched only `billing/`. Anyone
on Earth, not signed in, gets the `public` folders the same way; a project with
nothing public does not exist for them.
