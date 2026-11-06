# Troubleshooting and FAQ

Warnings start with `warning:` and never stop a command. Errors start with
`error:`, and the command did nothing (`vl` changes the repository in
transactions). Run `vl doctor` first when something is off: it checks the
machine and the repository and explains what it finds.

* [Secrets and policy](#secrets-and-policy)
* [Cloaking and keys](#cloaking-and-keys)
* [History, tags and revisions](#history-tags-and-revisions)
* [Remotes](#remotes)
* [The working copy and the filesystem](#the-working-copy-and-the-filesystem)
* [Locks, crashes and integrity](#locks-crashes-and-integrity)
* [FAQ](#faq)

## Secrets and policy

### `warning: X quarantined: looks like a secret (RULE at line N: …)`

The scanner found a credential in a public file, so the file (or this edit
of it) was not recorded. It's still on disk. Remove the secret, or cloak,
isolate or `expose --force` the file, or `vl restore X` to drop the edit.
See [Quarantine](secrets-and-visibility.md#quarantine).

### `warning: policy tries to make built-in secret path X public; ignored (use `public!` / `vl expose --force` to override)`

A plain `public` rule (maybe from `vl expose X`) matches a built-in secret
such as `*.pem`. It has no effect, and the warning repeats on every command
**until you delete the rule from `.veilpolicy`**, even if a later `public!`
rule now applies. Use `vl undo` right after `vl expose`, or edit the file.

### `warning: N local path(s) keep the protection you accepted: .veilpolicy would weaken it, and that change came from a merge, pull, checkout, restore or undo (or a symlinked policy file) rather than your own edit (…)`

Someone else's `.veilpolicy` change would publish, uncloak or stop scanning
one of your local files. Your files keep their protection. Review with
`vl policy show`; apply with `vl policy accept`, or remove the rule
yourself. See [the accepted policy](secrets-and-visibility.md#the-accepted-policy-when-an-incoming-change-is-held-back).
A directory listed with a trailing `/` (`.git/`) is held back as a whole.

When the warning says instead that the paths are held back "through a
change … that you have not accepted, or through your own edit", you edited
`.veilpolicy` on top of such a change and your edit could not be applied
without it (the warning before it says why). `vl policy show` lists both;
`vl policy accept` applies the file as it is.

### `warning: .veilpolicy is missing: the policy you accepted on this device still applies …`

`.veilpolicy` was deleted (or a change you pulled deleted it). Deleting it
never lifts protection. `vl restore .veilpolicy` brings it back;
`vl policy accept` accepts having no policy.

### `warning: .veilpolicy is a symlink: Veil applies the rules of the file it leads to …`

Veil follows the link, but records no change to it, and a change in the
target that weakens what you accepted waits for `vl policy accept`. Replace
the link with a copy (`cp --remove-destination "$(readlink .veilpolicy)" .veilpolicy`)
to record and share the policy.

### `warning: cannot read .veilpolicy (…); until it is fixed, snapshots apply the policy you accepted on this device`

`.veilpolicy` is unreadable (permissions), a directory, a symlink that
dangles or loops, or a symlink to a file whose name does not contain
`veilpolicy` (Veil never parses an arbitrary file as a policy). Commands go on under the policy you accepted; fix the
file (`chmod 644 .veilpolicy`). `vl policy accept` and `vl cloak` refuse
until then.

### `warning: N matching file(s) already exist in plaintext in earlier snapshots (e.g. X). New snapshots are protected; rotate any secrets they contain.`

You cloaked or isolated a path that was already recorded in plaintext.
Older snapshots (and any remote they were pushed to)
still contain it. Rotate the secrets.

### A rule in `.veilpolicy` behaves like `isolate`

A rule with an unknown tier, no tier, or an invalid scope (`local`,
`embargo/…`, upper case) is treated as `isolate`, with a warning. Check
with `vl policy check PATH`.

## Cloaking and keys

> Today's client, before the server; this changes when the server lands (see [OVERVIEW.md](../OVERVIEW.md) and [VISIBILITY.md](../VISIBILITY.md)).

### `error: you hold no current key for scope 'S' (create it with `vl scope create S`)`

You ran `vl cloak … --scope S` (default `team`) for a scope you are not a
member of. If the scope exists (`vl scope list` shows `no access`), ask an
admin to grant you; **don't** create it. If it doesn't exist, create it.

### `warning: could not cloak X (no key for scope 'S'); it was kept local-only`

The policy says to cloak `X` under `S`, but you don't hold `S`'s key, so
Veil can't seal it. It is not recorded (and never published). Ask an admin
for access, then the next command records it.

### `R` files in `vl status`, `redacted X (cloaked:S; no key; left out of the working copy)`

Cloaked files you can't read are kept in history and left out of your
working copy. The reason in brackets says why: `no key` (you are not a
member of `S`), `withheld by a public remote` (see the next entry) or
`embargo …; not released`. They appear automatically (`Filled in N file(s) that became
readable`) after an admin grants you the scope and pushes, and you pull.
From a **public** remote they never appear: public remotes don't carry
cloaked content at all.

### `note: N cloaked file(s) (scope 'S') withheld: this is a public remote, and public remotes never deliver cloaked content. …`

You cloned a public mirror. The cloaked files' names are in history, but
not their content, and no pull from the mirror will bring it, even after
a grant. Ask a member of `S` to grant you (`vl scope grant S <key>`; your
key is in `vl identity show`), then clone the **team** remote, or add it
(`vl remote add origin …`) and `vl pull origin`.

### `error: X is cloaked under scope 'S' and was withheld: this repository's content came from a public remote, …`

`vl cat` (or `vl restore`) of a cloaked file in a clone of a public
mirror. As above: once granted, clone or pull from a team remote.
`vl files` shows such files as `(redacted)`, and `vl diff` / `vl show` as
`(content hidden: cloaked:S; withheld by a public remote)`.

### `error: X is cloaked under scope 'S' and you hold no key for it. …`

The content is here, sealed, but you are not a member of `S`. Share your
public key (`vl identity show`) with a member, who runs
`vl scope grant S <key>` and pushes; then `vl pull`. `vl diff` and
`vl show` say `(content hidden: cloaked:S; you hold no key)`.

### `error: X is under embargo E, which is not released yet …`

The file belongs to an embargoed merge you can't read. `vl show REV`
gives the deadline (`Embargo   : E (until …)`); after the release, pull.

### `warning: key ring for scope 'team': exists on both sides with different keys; the incoming key ring was not merged`

Your repository and the remote each created their own `team` scope,
usually because you ran `vl init` and then pulled instead of cloning. The
rings can't be merged. Delete the directory and `vl clone` the remote. See
[Use `vl clone`](teams-and-remotes.md#use-vl-clone-not-vl-init--pull).

### `error: … that public identity has a signing key but no proof that it belongs to …`

The key you were given is the shorter form an earlier `vl` printed (member
id plus signing key, 128 hex digits), or was pieced together. The current
form adds a signature that ties the two keys together, so nobody can claim
someone else's signing key. Ask for the `public key` line of `vl identity
show` from this `vl` (256 hex digits) and grant again.

### `warning: that is a short public key without a signing key: their signatures will show as unknown.`

You granted with a member id instead of the full public key. Ask for the
full key (`vl identity show`, line `public key`) and grant again.

### `error: crypto error: the local vault (.veil/local/vault.sealed) cannot be opened with this identity's key: …`

Your identity was replaced. Run `vl identity recover-vault`. See
[Recovering a vault](maintenance.md#recovering-a-vault).

### `error: an identity already exists (use --force to replace it; you will lose access to scopes granted to it)`

Read [Replacing your identity](maintenance.md#replacing-your-identity)
before using `--force`.

## History, tags and revisions

### `main` moved and I didn't want it to

`vl commit` moves tags that pointed at the parent; `vl merge` moves tags at
the change merged into. Put it back with
`vl tag set main -r REV --allow-backwards`, or `vl undo`. See
[Tags](getting-started.md#tags).

### `error: moving tag 'main' would go backwards or sideways (use --allow-backwards)`

`vl tag set` only moves a tag forward (to a descendant) unless you pass
`--allow-backwards`. Make sure you aren't about to drop commits from a
pushed tag.

### `error: revision 'X' not found`, `change id prefix 'X' is ambiguous`

Change ids use the letters `k`–`z`; snapshot ids are hex and need at least
4 digits. Use a longer prefix. See [Revisions](getting-started.md#revisions).

### `error: change 'X' is divergent (N visible snapshots); use a snapshot id`

Two visible snapshots share a change id (for example, the same change was
rewritten on two machines). Pick one by snapshot id; `vl abandon` the other
if you don't need it.

### `vl status` doesn't show my merge conflict

In a repository at format 4 it does: the change on top of the merge holds
the conflict, listed with `recorded on` the merge. In an older format (or
for a merge under an embargo) conflicts are markers in the file, recorded
on the merge only, which is `@-` after `vl merge`: use `vl log` (`×` marks
it), then `vl edit` it and fix the files there. See
[Conflicts](getting-started.md#conflicts).

### `vl resolve` says I cannot resolve a conflict / my edit of a conflicted file is "held back"

One version in the conflict is sealed for a scope you are not in (`vl
resolve --list` says `not readable here`). You see it as a `(not shown: …)`
line, and an edit or a deletion by you would drop content you cannot read,
so it stays local. Ask a member of the scope to resolve it, or keep a
version you are allowed to choose with `vl resolve PATH --ours|--theirs`.

### `warning: edit of X not recorded: this line is under embargo E, whose content you cannot read, …`

You are working on top of an embargoed merge you hold no key for. Recording
your edit would silently revert the hidden fix, so it stays on disk and is
recorded after the release. Work on the merge's first parent instead
([Embargoes](embargoes.md#working-on-an-embargoed-line)).

### `error: policy violation: cannot merge under a new embargo: … already carries unreleased embargo E, and embargoes cannot overlap; …`

Veil allows one unreleased embargo per line. Release `E` first, or
embargo the second fix on a separate line. See
[One embargo per line](embargoes.md#one-embargo-per-line).

### `error: '…' is in the past; an embargo deadline must be in the future`

`--until` takes a future time: `+7d`, `+12h`, `2026-12-01`,
`2026-12-01T09:00:00Z`. To publish now, `vl embargo release ID`.

## Remotes

> Today's client, before the server; this changes when the server lands (see [OVERVIEW.md](../OVERVIEW.md) and [VISIBILITY.md](../VISIBILITY.md)).

### `rejected main (remote has diverged: not a fast-forward)` / `error: 1 tag was rejected (main): origin has changes you don't have. …`

Someone pushed to `main` since you last pulled. `vl pull`,
`vl merge origin/main`, `vl push`. The other tags were pushed; the push
exits 1 so that scripts notice. `vl push --force` overwrites the remote's
`main` instead.

### `skipped T (cloaked tag is never pushed to a public remote)`, `skipped T (… embargo …)`

Held back by design; a push of all tags still exits 0. If you named the
tag (`vl push -t T`), the push fails with
`error: requested tag was not pushed: T`.

### `warning: tag 'main' has diverged from origin/main; merge with `vl merge origin/main``

The pull updated `origin/main` but left your `main` alone. Merge, then
push.

### A file disappeared on the public mirror

It was cloaked by policy (`vl cloak`, or a `cloak` rule in `.veilpolicy`)
and that change reached a pushed tag: to the public, a cloaked file is
absent. A public file merely *edited* in a cloaked workspace does not
disappear: public readers keep its last public version (see
[Cloaking for a team](secrets-and-visibility.md#cloaking-for-a-team)).
(Cloaked edits recorded by Veil builds older than this rule carry no public
version and still show as deleted.)

### `vl upgrade --remote` on an SSH remote

`vl upgrade --remote NAME` reaches an SSH remote over SFTP, like `vl push`
and `vl pull`. Releases before this fix treated the URL as a local path:
they failed with `not found: Veil repository (run `vl init`)` and left an
empty directory named after the URL (`ssh:/…` or `user@host:…`) in your
working copy. Delete such a directory if you find one.

## The working copy and the filesystem

### `Working copy now at: …`, `Updated N files, removed M`

Informational: the command moved your working copy (`vl new`, `vl edit`,
`vl undo`, a rebase of `@`) and updated the files on disk to match.

### `kept X (local edit not in history, e.g. quarantined; left as is instead of being overwritten)`

A checkout would have overwritten a file whose content isn't in history
(a quarantined edit, an isolated file). Veil never overwrites what it
didn't write. Look at the file; the next snapshot records or quarantines it
as usual.

### `kept X (X/ holds files that are in no snapshot …)` or `kept X (X is a file that is in no snapshot …)`

The snapshot being checked out has a file where your directory has a
folder that still holds files in no snapshot (an isolated `private/`, an
ignored `target/`, untracked work), or a folder where you have a file in no
snapshot (a quarantined `cfg`). Veil never deletes what it did not write,
so it kept yours and did not write the snapshot's version there. The next
snapshot records the working copy as it is (`vl status` shows the
snapshot's file as deleted). To take the snapshot's version instead, move
`X` out of the way and run `vl restore X`.

### `N inner/` in `vl status`, `kept inner/ (a Veil repository of its own, …)`

`inner/` holds a `.veil` directory: it is a repository of its own (a
vendored project, a monorepo member, or `vl init` run in the wrong place).
As Git does with an embedded repository, this repository records nothing
in it, whatever `.veilpolicy` says: its cloaked files are plaintext on
disk, and only its own policy knows they are secret. Commit and push its
files from inside it. If this repository recorded files there before,
they show as deleted (they stay on disk), and a checkout never writes or
removes anything inside `inner/`. `vl scan` skips it (run `vl scan` in
it). If `inner/.veil` was a mistake, remove it (`rm -r inner/.veil`) and
the files are recorded again.

### `failed X (File name too long …; left out of the working copy …)`

The filesystem refused that one path: a name longer than it can hold
(255 bytes on most filesystems), a character it does not accept, or a
directory you cannot write to. The rest of the checkout went ahead, and
the file stays in history as it is (`vl status` lists it as `R`); every
command tries again. Rename it on a machine that can check it out, and
commit that.

### `Finished the interrupted move of the working copy to workspace 'X'`

An earlier `vl ws switch`, `vl new`, `vl edit` or `vl undo` was killed (or
failed) while it replaced your files. This command finished the move before
recording anything. Nothing was lost: files the move did not put there were
kept.

### `error: cannot undo '…': …`

The command `vl undo` would undo next (the last one, or the one before what
earlier undos took back) changed something the operation log does not hold
(a key ring, a remote, the local vault, the accepted policy). Restoring an
older view would not revert it, so `vl undo` refuses rather than undo an
unrelated, earlier command. Do what the message says. To go back further
anyway, use `vl op log` and `vl op restore ID`.

### `error: cannot undo '…': it would remove workspace 'NAME', which holds edits recorded since`

Undoing `vl ws new NAME` would delete the workspace with the edits recorded
in it since. Nothing was changed. To go back anyway, pick an operation in
`vl op log` and `vl op restore ID`; the operation log keeps those edits.

### `error: nothing to redo: the last command was not an undo`

`vl redo` only takes back undos, and any other command after them (editing
files aside) clears what could be redone. `vl op log` still lists every
state; `vl op restore ID` returns to one.

### `error: X was not recorded in workspace 'NAME': …`

`vl ws write` wrote the file, but the policy keeps that path out of history
(an isolated `.env` or `*.pem`, an ignored path) or the scanner quarantined
it. A virtual workspace has no local files, so nothing was kept. Check the
path, or change `.veilpolicy`.

### My isolated file is gone: can I get it back?

Every snapshot backs isolated files (`.env` & co) up into the local vault,
and the backup of a file that disappears is kept for 30 days.
`vl secret files` lists them; `vl secret recover PATH` writes one back
(never over an existing file).

### `warning: the working copy was stale; your edits were saved as change X`

The repository moved on without your files (an interrupted command, a
restored backup, another process). Your files were saved as change `X`
rather than lost. Find it with `vl log`, and squash, rebase or restore from
it.

### `warning: A and B differ only in case or Unicode normalisation; a checkout on a case-insensitive filesystem (macOS by default) will refuse this snapshot. Rename one of them`

Two names collide on macOS. Rename one. To rehearse a macOS checkout on
Linux: `VEIL_FS_FOLDING=macos vl edit REV`. See the README's
[platform notes](../../README.md#case-insensitive-filesystems).

### `error: … ` followed by `hint: the repository already moved to that snapshot. To work here meanwhile, move the working copy back without touching files: `vl --no-snapshot undo``

A checkout was refused because names would collide on this filesystem. Do
what the hint says, then rename the files (on a machine where they don't
collide, or from the commit that introduced them).

### `warning: skipped X: cannot read it (…); its last recorded version, if any, is kept. Fix its permissions or `vl ignore X``

Fix the permissions, or ignore the path.

### `warning: skipped NAME: the file name is not valid UTF-8, so Veil cannot record it.`

Veil records UTF-8 names only. Rename the file.

### `warning: X is tracked but is now a symlink or special file; Veil never follows it and keeps the recorded version`

Veil 1.0 doesn't record symlinks, and never writes through one. Replace the
link with a regular file, or ignore the path.

### `vl init` in a Git checkout: is `.git/` recorded?

No. VCS metadata (`.git`, `.jj/`, `.hg/`, `.svn/`) is ignored by the
engine at any depth, whatever `.veilpolicy` says, unless a `public!` rule
names the directory itself. Versions of `vl` before 1.0 recorded `.git/`;
the next snapshot with this version records it as deleted (your `.git/` on
disk is left alone), but earlier snapshots keep it, so treat anything
secret in `.git/config` (tokens in remote URLs) as exposed to whoever has
those snapshots.

### A mounted workspace says `Transport endpoint is not connected`

The process serving the mount (`vl ws mount`) died. Nothing written there
is lost: it is in `.veil/local/mounts/NAME/`. `vl ws unmount NAME` detaches
the dead mount and records it; or `vl ws mount NAME DIR` again, which
picks it up as it was. `vl doctor`, and every `vl` command meanwhile, say
which mount it is (`the mount of workspace NAME at DIR lost its process`).

### `warning: … the mount's version was saved as change X`

The workspace changed under its mount (another command recorded into it)
at a file you had also changed in the mount since it was last recorded.
Your version is in change X, on top of what the mount showed before; the
mount now shows the workspace's. `vl diff -r X`, then `vl merge X` or
`vl abandon X`. See
[mounts](workspaces-and-agents.md#vl-ws-mount-a-workspace-as-a-directory).

### `error: … is busy …; its edits are recorded, but it stays mounted`

`vl ws unmount` does not pull a mount from under a program: a file is
open there, or a shell has `cd`ed into it. Close it and run `vl ws
unmount` again (`lsof +D DIR` finds the culprit). Everything written so far
was recorded.

### `warning: workspace 'X' no longer exists; attaching to 'Y'`

The workspace your directory was attached to was removed (perhaps by
`vl ws rm` from elsewhere, or an undo). `vl ws list`, then `vl ws switch`.

### Exit status 141 after `vl log | head`

`head` closed the pipe before `vl` finished writing. `vl` stops printing,
finishes the command (the repository is not affected) and exits with 141,
as Git does (128 + SIGPIPE). Shells only show it with `set -o pipefail`.
`vl log -n N` avoids it. If standard output fails for another reason (a
full disk), `vl` says `error: could not write to standard output: …` and
exits 1.

## Locks, crashes and integrity

From format 6 commands record their operations without the repository
lock: only key-ring, vault and `repo.json` changes, `vl gc` and `vl
upgrade` take it, for milliseconds to seconds, and pushes take a remote's.
A `vl` killed while it records leaves its new objects in
`.veil/objects/incoming/tx-…`, which the next command removes once that
process is provably gone (`vl fsck` notes the ones it keeps). Two
commands recording the same workspace's directory take turns on
`.veil/local/wc/ws-NAME.lock`, which the system releases when a process
ends.

### `error: the working copy keeps moving under this command (another vl is running here?)`

Other commands kept recording or moving this workspace while this one
tried to record it, ten times in a row. Run it again.

### `error: the repository was upgraded while this command ran; run the command again`

`vl upgrade` ran while this command was working; nothing was recorded.

### `error: operation … named by .veil/op_heads/… (run vl fsck)`

A head of the operation log names an operation that is not there (a
damaged disk, or a file planted by hand). `vl fsck` names the file;
remove it if the operation is gone for good.

### `error: repository is locked: held by …, which cannot be proven gone from this machine; if it is, remove .veil/lock`

Another `vl` holds the lock, or held it on another machine (common on
network filesystems). Locks left by a crashed `vl` on the same machine are
taken over automatically. If you're sure nothing is running, delete
`.veil/lock`. `vl doctor` describes the holder, such as
`pid 4242 on build-host (lease renewed 2m 05s ago)`. `legacy lock file`
means an old `vl` wrote it; `lease renewal time unreadable: N` means the
file holds no valid time (it is damaged or was written by hand).

### `error: repository is locked: held by …, which is still running but no longer renews its lease`

The process named holds the lock and still exists, but stopped renewing
it: it is suspended (`Ctrl-Z`, a stopped debugger) or stuck on a hung
disk. Resume or end it; its lock is taken over as soon as it exits. A
`vl` that was killed but not yet reaped by its parent (a zombie, `Z` in
`ps`) counts as exited. On systems that hide other users' processes
(`/proc` mounted with `hidepid=2`, systemd's `ProtectProc=invisible`), a
lock held by another user's `vl` is never taken over while that process
exists, since a missing `/proc` entry is no proof that the holder is gone;
if it stops renewing, it is reported this way.

### `error: repository is locked: this process's repository lock was taken over; the operation was not recorded`

This `vl` stalled long enough (suspended laptop, frozen network mount) for
another process to take the lock over. Nothing was recorded. Run the
command again.

### `vl fsck` reports `Corrupt:`

Restore the damaged objects from a remote that has them: `vl pull --full`.
`vl gc` refuses to delete anything while the store is damaged.

### `error: unsupported format: this repository uses format N and needs vl X or later`

The repository was upgraded by a newer `vl`. Upgrade `vl` (see the
README's [Install section](../../README.md#install)).

## FAQ

**Is there a staging area, or an `add` command?** No. Every command records the
working copy. Keep things out with `.veilpolicy`.

**How do I amend the last commit?** Edit it in place with `vl edit @-` (then
`vl new` to start something new), or fold `@` into it with `vl squash`.
Reword it with `vl describe -r @- -m …`.

**Where is my work after `vl undo`?** Unrecorded edits on disk are kept.
Everything else is in the operation log: `vl op log`, `vl op restore ID`.

**Can I use Veil and Git in the same directory?** Veil never records
`.git/` (see above), but both tools would track the same files, and Veil
does not interoperate with Git: it imports, exports and syncs nothing with
it.

**Is my `.env` safe?** It's never recorded or pushed, by any command,
unless a policy you accepted says `cloak` (encrypted for a scope) or
`public!`. It is backed up in your local vault. Your machine's disk is
still your responsibility.

**Can a teammate see my isolated files?** No. They never leave your
machine.

**Can the server see cloaked files?** No, it stores ciphertext. It can see
their names, sizes and who the scope members are. See
[what isn't protected](secrets-and-visibility.md#what-is-protected-and-what-isnt).

**Does Veil work on Windows?** Not yet: Linux and macOS only.

**Where do I report a bug?** Include `vl --version` and the output of
`vl doctor`.
