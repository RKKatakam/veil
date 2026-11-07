# Teams and remotes

**Veil is server-centric** ([OVERVIEW.md](../OVERVIEW.md)): a remote is a
project on the Veil server, and the server decides who sees what
([VISIBILITY.md](../VISIBILITY.md)). Signing in, groups, folder access and
secrets are in [The Veil server](the-server.md); this page covers remotes,
pushing and pulling, and recovering from crashes.

1. [Remotes](#remotes)
2. [Push and pull](#push-and-pull)
3. [Teammates](#teammates)
4. [Recovering from crashes](#recovering-from-crashes)

## Remotes

```text
$ vl remote add origin veil://hub.example.com/acme
Added remote origin → veil://hub.example.com/acme
$ vl remote list
origin  veil://hub.example.com/acme
```

* A remote is `veil://host[:port]/project` (or `https://host[:port]/project`).
  `vl clone veil://hub.example.com/acme` sets it up as `origin` for you.
* There are no other kinds of remote: paths, shared drives and SSH or SFTP
  URLs were removed with the simplification pass, and `vl remote add`,
  `vl clone`, `vl push` and `vl pull` refuse them. A repository that still
  names one says so on push or pull; replace it with
  `vl remote rm origin` and `vl remote add origin veil://…`.
* A remote name is letters, digits, `-`, `_` and `.` (not first), as in
  `origin`: it becomes the `NAME/` of the remote tags.
* `vl remote rm NAME` removes a remote from the configuration, and its
  `NAME/TAG` remote tags (nothing on the server).

## Push and pull

```text
$ vl push
  pushed main → e7645a71
Sent 6 object(s) to origin
$ vl pull
  updated main → b90dc04e
Pulled 3 object(s) from origin
```

| Command | Does |
|---|---|
| `vl push [REMOTE] [-t TAG…]` | Send tags (all by default) and their history. `REMOTE` defaults to `origin`. Each tag moves its branch on the server only if nobody moved it meanwhile |
| `vl push --force` | Move branches that diverged on the server (admins only) |
| `vl pull [REMOTE]` | Fetch what you may see; update `REMOTE/TAG` (removing those of branches gone from the server) and create or fast-forward local tags |

Like everywhere in Veil, **only tags travel**, and **a pull never moves
your working copy**: `vl rebase -d main` after pulling.

* **A branch that moved on the server is rejected, not overwritten.** The
  push says so; pull, merge (`vl merge origin/main`) and push again.
* **Release tags never move on a pull.** If somebody moved an annotated
  release tag such as `v1.0` on the server, `vl pull` keeps yours, with its
  signed annotation, records theirs as `origin/v1.0`, and warns at every
  pull: `origin moved release tag v1.0 from 3f2a91c0 to 9d81e0b2; your
  release tag v1.0 stays at 3f2a91c0`. Compare with
  `vl diff --from v1.0 --to origin/v1.0`; take theirs only on purpose, with
  `vl tag set v1.0 -r origin/v1.0 --force`.
* **A tag you deleted stays deleted.** The next `vl pull` doesn't bring it
  back while the server's branch is still where it was (`kept deleted
  experiment`), and `origin/experiment` keeps showing what the server holds.
  If somebody moves the branch on the server to work you haven't seen, the
  pull brings it back and says so: new work is never hidden by an old
  deletion.
* **A pull removes `REMOTE/TAG` for branches the server no longer has**
  (`pruned origin/experiment`). Your own tag of that name is kept, with a
  warning: delete it too, or your next `vl push` publishes it again.
* **`pre-push` hooks** run before a push ([Hooks](hooks.md)).

## Teammates

Everything about people is on the server ([The Veil server](the-server.md)):
a teammate signs in with `vl login`, an admin adds them to a group
(`vl group add finance bob`, confirming their device's fingerprint the first
time), and they clone with `vl clone veil://hub.example.com/acme`. Removing
someone from their last group (`vl group remove finance bob`) takes effect on
their next request and rotates the secret key away from their devices.

**Use `vl clone`, not `vl init` and a pull.** `vl init` creates a **new**
`team` key ring with you as its only member; a later pull of a project that
has its own can't reconcile the two (the incoming one is not merged, with a
warning). If this happened, delete that directory and `vl clone`.

## Recovering from crashes

Veil is built to survive `kill -9`, power loss and full disks without
losing recorded work. What you may see:

**A lock left behind.** Every command that writes takes a lock
(`.veil/lock`) recording the machine and process holding it. A lock left by
a crashed `vl` on the same machine is taken over automatically by the next
command. `vl doctor` shows the state:

```text
$ vl doctor
…
Repository /tmp/vdoc/team
  ok    opens: format 3, id 05710380e40e4e83bbfdafb25d9423a2, operation 49596559, workspace 'default'
  note  a stale lock from pid 12345 on build-box (…) is left (holder pid 12345 is no longer running)
        the next command reclaims it automatically
```

If a command fails with `repository is locked: held by …, which cannot be
proven gone from this machine; if it is, remove .veil/lock`, the holder is
on another machine (a network filesystem) or can't be checked. Make sure
no `vl` is running there, then delete `.veil/lock`.

**A stale working copy.** If the repository moved on while your files
didn't (an interrupted command, a restored backup), the next command saves
what is on disk rather than overwriting it:

```text
warning: the working copy was stale; your edits were saved as change <id>
```

The edits are in that change: `vl log`, then `vl squash`, `vl rebase` or
`vl restore --from <id>` to bring them where you want them.

**An interrupted clone** is refused by the next command (`vl clone` did
not finish) rather than shown half empty: delete the directory and clone
again. **An interrupted push** published nothing: objects go up first, and
the branches move in one step at the end; run `vl push` again.

**Checking integrity.** `vl fsck` verifies every object, the key rings,
embargo records and the operation log, changes nothing, and exits 1 on
corruption. See [Maintenance](maintenance.md).

Next: [Maintenance](maintenance.md).
