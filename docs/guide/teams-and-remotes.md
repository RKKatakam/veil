# Teams and remotes

A Veil **remote** is another Veil repository: a directory (local disk, a
mounted share) or a directory on any machine you can `ssh` to. The server
needs SSH with its SFTP subsystem and nothing else: no `vl`, no daemon.
For GitHub, see [Using Veil with GitHub](github.md).

1. [Adding remotes](#adding-remotes)
2. [Team remotes and public remotes](#team-remotes-and-public-remotes)
3. [Push and pull](#push-and-pull)
4. [Onboarding a teammate](#onboarding-a-teammate)
5. [Removing a teammate](#removing-a-teammate)
6. [Recovering from crashes](#recovering-from-crashes)

## Adding remotes

```text
$ vl remote add origin ../hub
Added team remote origin → ../hub
$ vl remote add build alice@build.example.com:/srv/veil/proj.veil
Added team remote build → alice@build.example.com:/srv/veil/proj.veil
$ vl remote add mirror ../mirror --public
Added public remote mirror → ../mirror
$ vl remote list
build  team  alice@build.example.com:/srv/veil/proj.veil
mirror  public  ../mirror
origin  team  ../hub
```

| URL form | Example |
|---|---|
| A path (relative to the repository root, or absolute) | `../hub`, `/mnt/share/proj` |
| scp-style SSH | `alice@build.example.com:repos/proj` or `…:~/repos/proj` (relative to the home directory) |
| SSH URL | `ssh://alice@build.example.com:2222/srv/veil/proj`, `ssh://host/~/repos/proj` |

* The remote doesn't need to exist: the first `vl push` creates it (also
  when several people push to the new remote at once). It creates one only
  in a new or empty directory: a push to a directory that holds other files
  and is not a Veil repository (a typo, `../proj` for `../proj.veil`) is
  refused.
* A remote name is letters, digits, `-`, `_` and `.` (not first), as in
  `origin`: it becomes the `NAME/` of the remote tags. A Veil remote and a
  [Git remote](github.md) can't share a name, since both record
  `NAME/TAG` remote tags.
* `~` and `~/` mean your home directory on the server, as with Git and
  `scp`. `~user` (another account's home) is refused: write the absolute
  path.
* SSH remotes use **your own `ssh`**, so `~/.ssh/config` host aliases, the
  agent, `known_hosts` and `ProxyJump` work as they do for Git. `VEIL_SSH`
  replaces the command.
* Cloaked content is encrypted before it leaves your machine. The server
  only ever stores ciphertext for it.
* `vl remote rm NAME` removes a remote from the configuration, and its
  `NAME/TAG` remote tags (not the remote's data).

## Team remotes and public remotes

| | Team remote (default) | Public remote (`--public`) |
|---|---|---|
| Public files | ✓ | ✓ |
| Cloaked files | ciphertext, for members to decrypt | withheld (the entry shows as redacted) |
| Cloaked descriptions and tags | ciphertext / ✓ | placeholders / never sent |
| Unreleased embargoes | the fix, for the embargo's scope | the pre-merge tree only |
| Key rings | ✓ | ✗: never sent (since BUG-077). Still visible: scope names, and the member id and signing key of whoever signed public snapshots or embargo records. Rings an older `vl` already pushed stay there; each public push warns about them |
| Team vaults (`vl secret set --scope team NAME`) | ✓ (encrypted and signed records) | ✗: never sent |
| Isolated files, local vault | never (they are not in history) | never |

A teammate outside a scope who pulls from a team remote gets ciphertext
they can't open: the files appear as redacted (`R`) until someone grants
them access.

Use a public remote for a published mirror. For GitHub use `vl git`, which
exports the same public view.

## Push and pull

```text
$ vl push
  pushed main → e7645a71
Pushed 6 object(s) to origin
$ vl pull
  updated main → b90dc04e
Pulled 3 object(s) from origin
```

| Command | Does |
|---|---|
| `vl push [REMOTE] [-t TAG…]` | Send tags (all by default) and their history. `REMOTE` defaults to `origin` |
| `vl push --force` | Overwrite tags that diverged on the remote |
| `vl push --delete TAG` | Delete `TAG` on the remote (delete it here first with `vl tag delete TAG`). See [Deleting a tag](#deleting-a-tag) |
| `vl pull [REMOTE]` | Fetch tags and history; update `REMOTE/TAG` (removing those of tags gone from the remote) and create or fast-forward local tags |
| `vl push --full` / `vl pull --full` | Walk and verify every object instead of trusting what the other side has; repairs damaged or missing objects |

Like everywhere in Veil, **only tags travel**, and **a pull never moves
your working copy**: `vl rebase -d main` after pulling.

**Diverged tags are rejected, not overwritten**, in both directions:

```text
$ vl push
  rejected main (remote has diverged: not a fast-forward)
Pushed 0 object(s) to origin
error: 1 tag was rejected (main): origin has changes you don't have. Run `vl pull origin`, `vl merge origin/main`, and push again (or `vl push --force` to overwrite them)
$ vl pull
warning: tag 'main' has diverged from origin/main; merge with `vl merge origin/main`
Pulled 3 object(s) from origin
$ vl merge origin/main -m "Merge bob"
$ vl push
  pushed main → 5f50d8ae
Pushed 5 object(s) to origin
```

The other tags are still pushed, but the push **exits 1**, as `git push`
does, so a script can tell "partially rejected" (1) from "nothing to do"
(0). Tags held back by design are listed as `skipped` and don't fail a
push of all tags (a cloaked tag on a public remote, a tag that would
publish an unreleased embargo), but a tag you named with `-t` that is
held back does.

The history of a rejected tag is not sent: which tags the remote takes is
decided before anything is uploaded, so retrying a rejected push doesn't
grow the remote.

### Deleting a tag

A plain `vl push` never deletes anything on the remote. To delete a tag
there, delete it here, then push the deletion:

```text
$ vl tag delete experiment
Deleted tag experiment
$ vl push --delete experiment
  deleted experiment on origin
```

* **A tag you deleted stays deleted.** The next `vl pull` doesn't bring it
  back while the remote's tag is still where it was (`kept deleted
  experiment`), and `origin/experiment` keeps showing what the remote holds
  until you delete it there. If a teammate moves the tag on the remote to
  work you haven't seen, the pull brings it back and says so: new work is
  never hidden by an old deletion.
* **Deleting on the remote is refused if someone moved the tag since** (to
  work you haven't seen): pull first, or add `--force`. A tag the remote
  doesn't have is not an error.
* **A pull removes `REMOTE/TAG` for tags the remote no longer has**
  (`pruned origin/experiment`). Your own tag of that name is kept, with a
  warning: delete it too, or your next `vl push` publishes it again.
* History is not deleted. The remote's snapshots stay until nothing
  references them and `vl -R <remote> gc` prunes them (see
  [Maintenance](maintenance.md)); every clone keeps what it pulled.

The same holds for GitHub: `vl git push --delete BRANCH` (see
[Using Veil with GitHub](github.md)).

Concurrent pushes to one remote are serialised by a lock on the remote. A
client that crashes mid-push leaves a lease that the next push takes over
after at most about 45 seconds.

## Onboarding a teammate

Bob joins Alice's project. Alice is an admin of the `team` scope (she ran
`vl init`).

**1. Bob creates his identity and sends Alice his public key.** The public
key is not secret; send it any way you like, but make sure it's really his
(compare it by voice or in person if the content matters).

```text
bob$ vl identity show
Created new identity for 'bob' at /home/bob/.config/veil/identity.json
name        bob
public key  veil1e75c0889f1c686c2af33c77446eff375283023c36ebdab2cda63c5aaedccdd370990f1e1afad9a5d72d744b2e5ed2682ff8c0df65fd66c7e3b5269927b27450709ca3335b6fa2c165dc7d5835c515e552701a1e7fb30aa23803dd042f5370554c532440362f00f34032895977cd394ff82e27e7fb8c603d0cfc6c2acb8f3c00a
…
```

**2. Alice grants him the scope and pushes** the updated key ring:

```text
alice$ vl scope grant team veil1e75c0889f1c686c2af33c77446eff375283023c36ebdab2cda63c5aaedccdd370990f1e1afad9a5d72d744b2e5ed2682ff8c0df65fd66c7e3b5269927b27450709ca3335b6fa2c165dc7d5835c515e552701a1e7fb30aa23803dd042f5370554c532440362f00f34032895977cd394ff82e27e7fb8c603d0cfc6c2acb8f3c00a --name bob
Granted scope team to bob; push to share the updated key ring
alice$ vl push
Pushed 0 object(s) to origin
```

(The key ring is sent even when no objects are: "0 objects" is normal.)

**3. Bob clones:**

```text
bob$ vl clone ../hub bob2
Cloned /tmp/vdoc/hub into /tmp/vdoc/bob2 (26 objects, 4 files)
bob$ cat bob2/secrets/notes.md
internal notes
```

If Bob clones *before* Alice granted him (or pushed), he gets the public
files and a note; the cloaked ones arrive with his next pull after the
grant:

```text
bob$ vl clone ../hub bobwc
Cloned /tmp/vdoc/hub into /tmp/vdoc/bobwc (6 objects, 2 files)
  note: 1 cloaked file(s) (scope 'team') you hold no key for. Share your public key (veil1e75c…c00a) with a member
  and ask them to run `vl scope grant team <key>` and push. They appear here on your next `vl pull` after that.
bob$ vl status
…
Redacted (unreadable here; kept in history, absent on disk):
  R secrets/notes.md  (cloaked:team; no key)

bob$ vl pull
Pulled 0 object(s) from origin
Filled in 1 file(s) that became readable (a key arrived or an embargo was released), removed 0
```

`vl clone SRC [DEST]` accepts the same paths and SSH URLs as `vl remote
add`, sets `SRC` up as `origin`, and starts a new change on `main` (or
`trunk`, `master`, or the first tag).

### Use `vl clone`, not `vl init` + pull

`vl init` creates a **new** `team` scope with you as its only member. If
you then pull a repository that has its own `team` scope, the two rings
can't be reconciled: yours is kept, theirs is not merged, and grants made
in theirs never reach you:

```text
dave$ vl init && vl remote add origin ../hub && vl pull
  updated main → 5f50d8ae
warning: key ring for scope 'team': exists on both sides with different keys; the incoming key ring was not merged
Pulled 26 object(s) from origin
dave$ vl scope list
…
team  admin  generation 0, 1 changes
    dave         admin  veil1c2b2cb…d800 (you)
```

If this happened, start over: delete that directory and `vl clone`.

### Admins

`vl scope grant … --admin` makes a member an admin, who may grant, revoke
and rotate. Have at least two admins per scope so that losing one identity
doesn't freeze the scope. Two admins changing a scope at the same time
diverge: the second to pull keeps their ring and gets a warning, and must
re-apply the other's change.

## Removing a teammate

```text
alice$ vl scope revoke team veil1e75c0889…c00a
Revoked. Scope team rotated to key generation 1: new content is sealed with a key
the revoked identity never receives. Content they already decrypted cannot be recalled; rotate secrets.
Push to share the updated key ring.
alice$ vl push
```

Revocation is **forward-only**: Bob keeps everything he could read before,
including every file still sealed under an older key generation. Rotate the
real secrets (passwords, API keys) that those files contain. Remove his
access to the remote itself (SSH keys, share permissions) as well.

If the scope has a [team vault](secrets-and-visibility.md#the-team-vault),
the revocation also lists every secret in it that Bob could read: rotate each
at its source and store the new value with `vl secret set --scope team
NAME`. Bob's own writes stop counting, and the values he last set are
re-signed by you so they don't vanish. `vl secret list --scope team
--exposed-to bob` shows what is still to rotate.

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

**Checking integrity.** `vl fsck` verifies every object, the key rings,
embargo records and the operation log, changes nothing, and exits 1 on
corruption. `vl push --full` / `vl pull --full` repair missing or damaged
objects from the other side. See [Maintenance](maintenance.md).

Next: [Maintenance](maintenance.md).
