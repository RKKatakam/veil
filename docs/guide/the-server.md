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
too). An admin compares it with you once, before your device receives the
project's secret keys.

**Another device of yours** signs in with the same command and name. It
waits until you confirm it from a device you already use, then signs in:

```sh
vl identity confirm 7C1B-0E44-93AD-2F18-B6C0    # on your laptop: the new device's fingerprint
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

Admins create groups, add people (who signed in once), and choose managers;
a group's managers add and remove other people in it, never themselves:

```sh
vl group create finance
vl group add finance alice bob
vl group manager finance carol
vl group list
```

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

## Secrets

- **New repositories encrypt shared secrets** (`.env`, `.env.*`, `.envrc`,
  Terraform state) on your device and sync them; the policy `vl init` writes
  says so. Only devices holding the project's key open them.
- **Personal private keys and credentials** (`id_rsa`, `id_ed25519`,
  `*.pem`, `*.key`, `.netrc`, …) never leave your device; the server refuses
  them.
- **Keys come from an admin's signature, for confirmed devices only.** When
  an admin adds you to a group, their `vl` grants you the key, but only for
  devices vouched for outside the server. The first time, it shows
  `confirm alice's device: 4F2A-…`; the admin checks it with you and runs
  `vl group add finance alice --confirm 4F2A-9C1E-77B0-D3E5-A1C2` (one
  person at a time). Devices
  you confirm yourself (`vl identity confirm`) get the key the next time an
  admin adds you. A server that lists a device of its own under your name
  gets nothing. A manager's addition gives you the folder but not the key,
  until an admin's device signs. Leaving your last group rotates the key
  away from all your devices; a removal that leaves you in another group
  says so.
- **An existing repository** starts syncing its secrets only when you ask,
  after seeing the list:

```sh
vl upgrade --sync-secrets --dry-run
vl upgrade --sync-secrets
```

## What someone without access sees

Bob is not in `finance`. His clone of `acme` has `src/` only: no `billing/`,
not even its name, and no trace of changes that touched only `billing/`. Anyone
on Earth, not signed in, gets the `public` folders the same way; a project with
nothing public does not exist for them.
