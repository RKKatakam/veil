# Troubleshooting and FAQ

Warnings start with `warning:` and never stop a command. Errors start with
`error:`, and the command did nothing (`vl` changes the repository in
transactions). Run `vl doctor` first when something is off: it checks the
machine and the repository and explains what it finds.

* [Secrets and policy](#secrets-and-policy)
* [Cloaking and keys](#cloaking-and-keys)
* [History, tags and revisions](#history-tags-and-revisions)
* [Remotes and Git](#remotes-and-git)
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

### `warning: N local file(s) keep the protection you accepted: .veilpolicy would weaken it, and that change came from a merge, pull, checkout or undo rather than your own edit (…)`

Someone else's `.veilpolicy` change would publish, uncloak or stop scanning
one of your local files. Your files keep their protection. Review with
`vl policy show`; apply with `vl policy accept`, or remove the rule
yourself. See [the accepted policy](secrets-and-visibility.md#the-accepted-policy-when-an-incoming-change-is-held-back).

### `warning: N matching file(s) already exist in plaintext in earlier snapshots (e.g. X). New snapshots are protected; rotate any secrets they contain.`

You cloaked or isolated a path that was already recorded in plaintext.
Older snapshots (and any remote or Git repository they were pushed to)
still contain it. Rotate the secrets.

### A rule in `.veilpolicy` behaves like `isolate`

A rule with an unknown tier, no tier, or an invalid scope (`local`,
`embargo/…`, upper case) is treated as `isolate`, with a warning. Check
with `vl policy check PATH`.

## Cloaking and keys

### `error: you hold no current key for scope 'S' (create it with `vl scope create S`)`

You ran `vl cloak … --scope S` (default `team`) for a scope you are not a
member of. If the scope exists (`vl scope list` shows `no access`), ask an
admin to grant you; **don't** create it. If it doesn't exist, create it.

### `warning: could not cloak X (no key for scope 'S'); it was kept local-only`

The policy says to cloak `X` under `S`, but you don't hold `S`'s key, so
Veil can't seal it. It is not recorded (and never published). Ask an admin
for access, then the next command records it.

### `R` files in `vl status`, `redacted X (no key; left out of the working copy)`

Cloaked files you can't read are kept in history and left out of your
working copy. They appear automatically (`Filled in N file(s) that became
readable`) after an admin grants you the scope and pushes, and you pull.
From a **public** remote they never appear: public remotes don't carry
cloaked content at all.

### `error: object … is not present in this store` from `vl cat`

The file is cloaked, and this repository was cloned from a public remote,
which withheld its content. `vl files` shows it as `(redacted)`.

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
[the pitfalls](coming-from-git.md#pitfalls).

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

`vl status` lists conflicts in `@` only, and after `vl merge` the
conflicted change is `@-`. Use `vl log` (`×` marks it), then `vl edit` it
and fix the files there. See [Conflicts](getting-started.md#conflicts).

### `warning: edit of X not recorded: this line is under embargo E, whose content you cannot read, …`

You are working on top of an embargoed merge you hold no key for. Recording
your edit would silently revert the hidden fix, so it stays on disk and is
recorded after the release. Work on the merge's first parent instead
([Embargoes](embargoes.md#working-on-an-embargoed-line)).

### `error: policy violation: cannot merge under a new embargo: … already carries unreleased embargo E, and embargoes cannot overlap; …`

Veil 1.0 allows one unreleased embargo per line. Release `E` first, or
embargo the second fix on a separate line. See
[One embargo per line](embargoes.md#one-embargo-per-line).

### `error: '…' is in the past; an embargo deadline must be in the future`

`--until` takes a future time: `+7d`, `+12h`, `2026-12-01`,
`2026-12-01T09:00:00Z`. To publish now, `vl embargo release ID`.

## Remotes and Git

### `skipped main (remote has diverged (non-fast-forward; use --force))`

Someone pushed to `main` since you last pulled. `vl pull`,
`vl merge origin/main`, `vl push`. The push still exits 0, so scripts must
check for `skipped`.

### `warning: tag 'main' has diverged from origin/main; merge with `vl merge origin/main``

The pull updated `origin/main` but left your `main` alone. Merge, then
push.

### `rejected main ([rejected] (fetch first))` / `error: some branches were rejected: …`

The Git branch moved on GitHub. `vl git pull`, `vl merge origin/main`,
`vl git push`. `vl git push --force` overwrites only what you last fetched.

### `warning: origin/B was force-pushed on the Git side (…); the Veil history it dropped is kept`

Someone rewrote the branch on GitHub. Your tags didn't move. Decide what you
want, then `vl tag set B -r … --allow-backwards` and push, or merge.

### `not recorded X (…; it stays in Git)`

A file in a Git commit was refused at import (a committed `.env`, a file
with a secret, a symlink, a submodule). Veil doesn't record it, and it is
not deleted from Git by later pushes. Remove it from Git yourself if it is
a leaked secret, and rotate the secret.

### `could not run git for fetch: … (is git installed? set VEIL_GIT to its path)`

`vl git` runs the `git` binary. Install Git or point `VEIL_GIT` at it.

### Commits on GitHub show `alice <>`

Veil exports the author it recorded. Set
`VEIL_USER="Name <email>"` before creating changes. See
[Credentials and authorship](github.md#credentials-and-authorship).

### A file disappeared on GitHub or the public mirror

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

### `warning: workspace 'X' no longer exists; attaching to 'Y'`

The workspace your directory was attached to was removed (perhaps by
`vl ws rm` from elsewhere, or an undo). `vl ws list`, then `vl ws switch`.

### `error: … Broken pipe` when piping into `head`

`vl log | head` currently panics when `head` closes the pipe (exit code
101). The repository is not affected. Use `vl log -n N` instead.

## Locks, crashes and integrity

### `error: repository is locked: held by …, which cannot be proven gone from this machine; if it is, remove .veil/lock`

Another `vl` holds the lock, or held it on another machine (common on
network filesystems). Locks left by a crashed `vl` on the same machine are
taken over automatically. If you're sure nothing is running, delete
`.veil/lock`. `vl doctor` describes the holder.

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
`.git/` (see above), but both tools would track the same files. Prefer
`vl git import` in a separate directory and push to GitHub with
`vl git push`.

**Is my `.env` safe?** It's never recorded or pushed, by any command,
unless a policy you accepted says `cloak` (encrypted for a scope) or
`public!`. It is backed up in your local vault. Your machine's disk is
still your responsibility.

**Can a teammate see my isolated files?** No. They never leave your
machine.

**Can the server see cloaked files?** No, it stores ciphertext. It can see
their names, sizes and who the scope members are. See
[what isn't protected](secrets-and-visibility.md#what-is-protected-and-what-isnt).

**Does Veil work on Windows?** Not in 1.0: Linux and macOS only.

**Where do I report a bug?** Include `vl --version` and the output of
`vl doctor`.
