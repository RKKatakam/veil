# Maintenance

1. [`vl gc`](#vl-gc)
2. [`vl fsck`](#vl-fsck)
3. [`vl doctor`](#vl-doctor)
4. [`vl upgrade`: repository formats](#vl-upgrade-repository-formats)
5. [Backups](#backups)
6. [Replacing your identity](#replacing-your-identity)
7. [Recovering a vault](#recovering-a-vault)

## `vl gc`

Packs loose objects into one compressed pack (with deltas between versions
of a file) and deletes objects nothing references any more.

```text
$ vl gc
Objects: 36 before (36 loose, 0 pack(s)), 36 reachable, 0 deleted, 0 pending deletion
Packed 36 object(s) into pack-c42f1e8179bb (6 delta, 20 compressed, 10 stored)
Storage: 0.02 MiB -> 0.01 MiB
```

* **Nothing reachable from the operation log is deleted.** Undo keeps
  working across `gc`. By default the whole operation log is kept.
* `--keep-ops-days N` prunes operations older than `N` days (the current
  one and its parents are always kept). Snapshots only those operations
  referenced become unreachable:

  ```text
  $ vl gc --keep-ops-days 0
  Objects: 48 before (0 loose, 1 pack(s)), 31 reachable, 0 deleted, 17 pending deletion
  Packed 48 object(s) into pack-5a16fe9a753d (7 delta, 28 compressed, 13 stored)
  Operations: pruned 18 of 20
  Storage: 0.02 MiB -> 0.02 MiB
  ```

* **Unreachable objects are deleted on a later run**, once they have stayed
  unreachable for the grace period (`--grace-minutes`, default 60), so a
  `vl` command running at the same time is never affected. `pending
  deletion` counts them.
* `--prune-now` deletes them at once. Only use it when no other `vl`
  process is running on the repository.
* `--level L` sets the zstd level (default 3); `--no-deltas` disables delta
  compression. A small edit of a large file is stored as a small delta up
  to about 64 MiB per version (the base and the new version must fit in
  zstd's 128 MiB window); above that only the parts within the window are
  shared.
* **A remote on a path is collected the same way**: `vl -R ../hub gc`.
  History un-tagged there (`vl push --delete`, `vl push --force`) is pruned
  after the grace period. In a bare repository such as a remote, `vl -R`
  runs `log`, `show`, `tag list`, `op log`, `gc` and `fsck`; other commands
  need a working copy and are refused.
* If part of the history can't be read, `gc` deletes nothing and says so.
  Run `vl fsck`.

In 1.0, `gc` rewrites everything it keeps into new packs (a new one every
128 MiB, so its memory stays bounded). On a large repository, run it
occasionally, not after every command. After `gc` with
`--keep-ops-days`, `vl evolog` may end with
`(older versions were removed by `vl gc`)`.

## `vl fsck`

Verifies the repository without changing anything: every object's hash,
reachability, key-ring signatures and hash chains, embargo records and the
operation log. It exits 1 on corruption.

```text
$ vl fsck
Checked 36 objects (19 snapshots, 8 trees, 13 files; 0 unreachable), 15 operations, 2 key rings, 0 embargo records
  0 redacted (expected), 1 note(s); use --verbose to list them
No corruption found
$ vl fsck -v
note: 2 predecessor snapshot(s) of the evolution log are not present (normal after clone or pull)
…
```

* `redacted` objects are content you hold no key for, or that a public
  remote withheld: expected.
* `unreachable` counts objects nothing references, loose or packed (`gc`
  keeps them, packed, through their grace period); they are verified too.
  A pack that can't be opened is a warning (`gc` refuses to run until it is
  removed); any reachable object it held is reported as missing.
* `-R PATH` checks another repository, including a bare remote on a path:
  `vl fsck -R ../hub`.
* To repair missing or damaged objects, fetch them from a remote that has
  them: `vl pull --full`. To repair a remote, `vl push --full`.
* Notes about a leftover lock, `.veil/lock.steal` or a sub-guard
  `.veil/lock.steal.<hash>` mean a `vl` was interrupted. They are
  harmless: the next command takes a dead holder's lock over (and first
  re-checks the objects it may have left unsynced), and the next takeover
  or `vl doctor` removes stale guards.

## `vl doctor`

Checks this machine and the repository you are in, changes nothing you care
about, and explains every problem it finds. Exits 1 if something is
broken.

```text
$ vl doctor
vl 0.1.0 (commit d0342039c517, repository format 3) on x86_64-unknown-linux-gnu

Setup
  ok    VEIL_HOME /home/alice/.config/veil ($VEIL_HOME)
  ok    identity 'alice' veil15dc25eaf411… (/home/alice/.config/veil/identity.json)
  ok    no leftover `ws exec` sandboxes in /tmp

Repository /home/alice/team
  ok    opens: format 3, id 05710380e40e4e83bbfdafb25d9423a2, operation 49596559, workspace 'default'
  ok    not locked
  ok    stat cache: 2 files, 1 KiB
  ok    vault opens: 1 files, 0 secrets

Filesystem
  ok    filesystem: tmpfs
  ok    durable write (fsync) in 15 µs
  ok    names: case-sensitive, byte-exact names
  ok    clock: 2026-11-04 04:11:02

Everything looks good.
```

It checks your identity (readable, valid, mode `0600`, retired identities
too), `VEIL_HOME`, leftover sandboxes, the repository's format and lock
(including lock takeover guards, `.veil/lock.steal` and
`.veil/lock.steal.<hash>`, that a `vl` crashing mid-takeover left behind:
it removes those whose holder has provably exited, which is the one thing
it changes, and names the rest), the stat cache, the vault, the filesystem (network mounts, `fsync`, case and
Unicode folding, see the README's [platform notes](../../README.md#platform-notes))
and the clock. `vl doctor --remotes` also checks every remote: a path
remote must be a Veil repository; an SSH remote is contacted (through your
`ssh`, like `vl push`), must be a Veil repository, and its clock is compared
with this machine's by the modification time of a probe file it creates and
removes in the remote's `.veil/`. Beyond 60 s it warns: locks on a shared
remote allow 2 minutes of clock difference between clients, and two clients
can be off in opposite directions. Use it when a push or pull to an SSH
remote reports a lock you do not expect.

Run it after installing, after moving a repository to another disk, and
whenever something behaves strangely.

## `vl upgrade`: repository formats

A repository records its format in `.veil/repo.json`. Every `vl` reads every
older format and keeps writing it, so **existing repositories keep working
without an upgrade**. `vl upgrade` opts in to what a newer format adds:

| Format | Adds |
|---|---|
| 1 | The first release: JSON trees |
| 2 | Binary trees, which make `vl status` faster |
| 3 | Standard cryptography: AES-SIV for sealed objects, HPKE key wrapping, independent signing keys |

```text
$ vl upgrade --dry-run
Would upgrade this repository from format 1 to format 3
  objects    76 (27 JSON tree(s), 0 binary tree(s))
  steps      verify, set-format, 3:hpke-ring-keys
  note: new content is sealed with AES-SIV and scope keys are wrapped with HPKE; existing sealed objects keep the legacy construction, their bytes and their ids (nothing is re-sealed), so snapshot ids and signatures do not change
  note: a remote still at format 1 or 2 refuses AES-SIV objects and HPKE key rings: upgrade it with `vl upgrade --remote <name>`; a member's clone at format 2 cannot pull them until it is upgraded
  …
$ vl upgrade
Upgraded this repository from format 1 to format 3
  …
  note: scope 'team': new key generation 3, wrapped to every member with HPKE; earlier generations stay reachable (and stay under the legacy key wrapping already published)
$ vl upgrade --remote origin
Upgraded remote 'origin' (../team) from format 1 to format 3
  …
  note: key rings were not re-keyed here (no identity: a remote is upgraded structurally); they move to HPKE when an admin who has upgraded their clone pushes (in a clone that is already at format 3, `vl upgrade` still moves the admin's rings)
```

* **Nothing is rewritten.** Old objects keep their bytes and ids, so
  snapshot ids, change ids and signatures stay valid.
* It runs `fsck` first and refuses if there is corruption (`--force`
  overrides). It is journaled and resumes after a crash.
* **Older `vl` releases can no longer read an upgraded repository.**
* **Order matters for a team.** Everyone upgrades `vl` first. Then upgrade
  the shared remote (`vl upgrade --remote origin`), and each member upgrades
  their clone. A format-1 or format-2 remote refuses format-3 objects, and a
  clone at an older format can't pull them.
* `vl upgrade --remote` works for path and SSH remotes (over SFTP, as push
  and pull reach them).
* **Admins: run `vl upgrade` even in a clone that is already at format 3**
  (a fresh clone of the upgraded remote, or one a non-admin upgraded). It
  moves the key rings you administer to HPKE ("Moved the key rings of this
  repository (format 3) to HPKE key wrapping"), then push. Members who are
  not admins get a note naming the scopes still waiting.
* `vl clone` creates a clone at the source's format.

Details: [`docs/FORMAT.md`](../FORMAT.md).

## Backups

What only exists on your machine:

| What | Where | Why it matters |
|---|---|---|
| **Your identity** | `$VEIL_HOME/identity.json` (default `~/.config/veil/`) | Without it you lose access to every scope you're in and to your vaults. Nobody can restore it for you |
| Retired identities | `$VEIL_HOME/retired/` | Needed to re-key vaults after `vl identity new --force` |
| **Isolated files and the vault** | your working copy, and `.veil/local/vault.sealed` in each repository | Never pushed anywhere, by design |
| Unpushed changes, tags and the op log | `.veil/` | Until you push |

* Back up `$VEIL_HOME` securely (it holds private keys): an encrypted
  backup or a password manager.
* A team remote is a backup of the history you pushed, cloaked content
  included (as ciphertext). Push to a second remote on another disk if you
  want two.
* To back up a whole repository, copy the directory (including `.veil/`)
  **while no `vl` command is running** on it, with your usual backup tool.
  After restoring, run `vl fsck`. If the repository and your files are out
  of step, the next command saves your files as a change instead of
  overwriting them (see [Recovering from crashes](teams-and-remotes.md#recovering-from-crashes)).

## Replacing your identity

`vl identity new --force` creates a new key pair. **Think twice**: every
scope you were in must grant the new key again. If you were a scope's only
admin, `vl identity new --force` warns first (for the repository you run it
in), and `vl identity recover-admin` hands your admin rights over afterwards
(below).

```text
$ vl identity new --force --name alice
Created identity alice veil15c991ab1c95…
The replaced identity was kept at /home/alice/.config/veil/retired/identity-1793766156152.json (delete it once no vault needs it)
Re-keyed the local vault of /home/alice/sec2
warning: other repositories' local vaults are still sealed by the replaced identity; run `vl identity recover-vault` in each. Scope admins must grant the new public key again; where you were an admin, `vl identity recover-admin` hands your admin rights over.
```

* The old identity is kept in `$VEIL_HOME/retired/` (mode `0600`). It
  still holds private keys: delete it once no vault needs it.
* Run `vl identity recover-vault` in every other repository you use (next
  section), and send the new public key to your scope admins.
* Until they grant it, cloaked files you edit can't be sealed and are kept
  local-only, with `warning: could not cloak … (no key for scope 'team')`.

**Admin rights.** Where the replaced identity was an admin, it can sign the
hand-over to the new one. In each repository:

```sh
vl identity recover-admin          # the replaced identity grants you admin rights
vl push                            # share the updated key rings
vl identity recover-admin --revoke-old   # later, once no device uses the old identity
```

`recover-admin` tries every identity in `$VEIL_HOME/retired/` (or `--from
FILE`). In scopes where the old identity was only a member, it says so: ask
an admin to grant your new public key. `--revoke-old` revokes the old
identity, which rotates the scope key.

**Undoing a replacement**: put the old identity back, keeping the new one
where `recover-vault` can find it:

```sh
cd ~/.config/veil
cp identity.json retired/identity-replacement.json
cp retired/identity-1793766156152.json identity.json
chmod 600 identity.json
vl identity recover-vault          # in each repository whose vault the new identity re-keyed
```

## Recovering a vault

Each repository's vault is sealed with your identity. If it was sealed by
another one, every command that needs it fails:

```text
error: crypto error: the local vault (.veil/local/vault.sealed) cannot be opened with this identity's key: it was sealed by another identity (was the identity replaced with `vl identity new --force`?) or is damaged. Run `vl identity recover-vault` to re-key it from the previous identity, or delete the file to start an empty vault
$ vl identity recover-vault
Re-keyed the local vault with the identity in /home/alice/.config/veil/retired/identity-1793766156152.json
```

`recover-vault` tries every identity in `$VEIL_HOME/retired/`, newest
first; `--from FILE` uses a specific identity file. If none opens it and
you don't need its contents (named secrets and the backups of isolated
files), delete `.veil/local/vault.sealed` to start an empty vault.

Next: [Troubleshooting and FAQ](troubleshooting.md).
