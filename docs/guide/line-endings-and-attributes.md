# Line endings and per-path attributes

Veil reads `.veilattributes` to decide three things per path: which line
endings a file is recorded and checked out with, whether it is shown and
merged as text or as binary, and which diff or merge *driver* applies.
There is no device setting like Git's `core.autocrlf`: what is recorded
never depends on whose machine recorded it.

## The file

`.veilattributes` has the syntax of Git's attributes files:

```text
# Normalise every text file to LF in history (Git's recommended setting).
* text=auto
# Windows scripts are checked out with CRLF.
*.bat   text eol=crlf
*.cmd   text eol=crlf
# Never converted, never shown or merged line by line.
*.png   binary
*.pdf   binary
# Lock files: both sides' lines on a conflicting merge.
Cargo.lock merge=union
```

* A pattern without a `/` matches a file name at any depth below the
  directory of the `.veilattributes` it is in; one with a `/` is matched
  against the path relative to that directory (`*` never crosses a `/`,
  `**/` matches any number of directories). A pattern ending in `/` never
  matches a file, as in Git.
* Files in subdirectories add to the root's, and win over it; within one
  file a later line wins over an earlier one.
* Macros (`[attr]mytext text eol=lf`) may only be defined in the
  top-level `.veilattributes`; `binary` is built in (`-diff -merge -text`).
* `.veil/local/attributes` holds this device's own overrides: it wins over
  every `.veilattributes` and is never synced.

`vl attr check` shows what applies to a path, and what Veil does with it:

```text
$ vl attr check run.bat logo.png Cargo.lock
run.bat: eol: crlf
run.bat: text: set
  veil line endings: text-crlf · diff: text · merge: text
logo.png: binary: set
logo.png: diff: unset
logo.png: merge: unset
logo.png: text: unset
  veil line endings: none · diff: binary · merge: binary
Cargo.lock: merge: union
Cargo.lock: text: auto
  veil line endings: auto-lf · diff: text · merge: union
```

`vl attr check --json` prints the same as data (`veil.attr-check/1`, see
[JSON output](../reference/json.md#veilattr-check1)).

## Line endings

| attributes | recorded | checked out |
|---|---|---|
| none, `-text`, `binary` | the bytes as they are | the bytes as recorded |
| `text`, `eol=lf` | CRLF normalised to LF | LF |
| `text=auto` | as `text`, if the file looks like text | LF |
| `eol=crlf` (with or without `text`) | CRLF normalised to LF | CRLF |
| `text=auto eol=crlf` | as `text`, if the file looks like text | CRLF, if it looks like text |

These are Git's rules (with `core.autocrlf=false`). A file "looks like
text" when it holds no NUL byte, no lone CR and few control characters.

Three rules keep your bytes safe:

* **Never lossy.** A file is normalised only when every line ending is
  CRLF. One with mixed line endings (CRLF and lone LF) or a lone CR is
  recorded exactly as it is, and Veil says so:

  ```text
  warning: notes.txt: its line endings are mixed (CRLF and LF); recorded unchanged (`.veilattributes` asks for LF line endings, and converting would change more than the line endings)
  ```

  (Git converts such a file anyway, with a warning.)
* **No silent re-recording.** Adding or changing `.veilattributes` never
  re-records a file that still holds its recorded version: a file
  committed with CRLF stays so in history, and a file checked out with
  CRLF is not taken for an edit when the attributes change. The first
  real edit of such a file records it as the attributes now say (its diff
  then shows every line changing). `vl status` tells you when files would
  change:

  ```text
  2 file(s) would change line endings (`.veilattributes` asks for other line endings than they were recorded with); run `vl renormalize` to re-record them
  ```
* **Edits are never overwritten.** Switching to another change replaces a
  file only if it holds exactly what was checked out (as written, with CRLF
  for `eol=crlf`, or something the attributes normalise to it).

### `vl renormalize`

`vl renormalize [PATH…]` re-records the files (all, or those under the
paths given) with the line endings the attributes ask for now. It is an
operation of its own: `vl undo` reverts it. It does not rewrite the
working copy. Like recording, it never makes a lossy conversion.

```text
$ echo '* text=auto' > .veilattributes
$ vl renormalize
Renormalized docs/old-notes.txt
Renormalized src/legacy.c
2 file(s) re-recorded (`vl undo` reverts it)
```

Under `text=auto`, an edit of a file whose recorded version holds a CR
keeps its line endings (Git's "safer autocrlf"); `vl renormalize` is the
way to normalise it.

## Diff and merge

* `binary` or `-diff`: `vl diff` and `vl show` say "binary
  content differs".
* `binary`, `-merge` or `merge=binary`: two different versions of the file
  are a conflict as a whole, never merged line by line.
* `merge=union`: a conflicting hunk takes both sides' lines, ours first
  (good for changelogs and lock files you regenerate anyway).
* `merge=text` (or no `merge`): the line merge; a binary-looking file
  conflicts as a whole.

### Drivers are defined on your device, never by a repository

`diff=NAME` and `merge=NAME` only *name* a driver. A name means something
only if **your device** defines it, in `$VEIL_HOME/config.toml` or the
repository's `.veil/local/config.toml` (which wins by name). Nothing in a
repository, not `.veilattributes`, not a tracked `config.toml`, can define a
command: a teammate's `* merge=pwn` does nothing but print a warning, and
the built-in merge is used.

```toml
# .veil/local/config.toml
[merge.lockfile]
command = ["/usr/local/bin/merge-lockfile", "%O", "%A", "%B", "%P"]

[diff.sqlite]
textconv = ["sqlite3", "-batch", "/dev/stdin", ".dump"]
```

* A **merge driver** is given three private files (`%O` the base, `%A`
  ours, `%B` theirs; `%P` is the path, `%L` the conflict marker size). It
  writes the result into `%A` and exits 0, or exits non-zero for a
  conflict. The files live in a fresh private directory under
  `.veil/local/tmp/` and are removed afterwards.
* A **textconv** gets the file's content on its standard input and prints
  the text to diff. `vl diff` and `vl show` use it; its output
  is never written to disk or cached.
* The program is an absolute path or a name on `PATH`, and is never a file
  inside the project (a teammate could change it). It runs in the
  repository's directory with a cleaned environment (as hooks do, see
  [Hooks](hooks.md)), and is stopped after 60 seconds (Ctrl-C stops it
  with `vl`).

**Confidentiality.** A merge driver is given the base only when the base's
audience is the merged result's: when the base is sealed for a scope and
the result is not, it gets an empty base, so no base-only text can reach a
public result. It is never run when the two sides are sealed for different
scopes (that stays a conflict), and what it produces is sealed like any
merged content. A textconv is your own tool, given plaintext you can read;
remember that whatever it does with it is up to it.

## What Veil does not support

`vl attr check` lists these as "not supported by Veil":

* `filter` (clean/smudge filters): Veil records the file as it is on disk.
  `vl attr check` warns about it.
* `ident`, `working-tree-encoding`: the bytes are recorded as they are.
* `export-ignore`, `export-subst`, `linguist-*`, `whitespace`,
  `conflict-marker-size`.

Also different from Git:

* Patterns match case-sensitively on every device (Git follows
  `core.ignorecase`, which is on by default on macOS).
* There is no `core.autocrlf` or `core.eol`: the attributes alone decide,
  and the native line ending is LF.
* `vl ws mount` shows files with their recorded line endings (LF for an
  `eol=crlf` file); writing either form back records no change.
* A `.veilattributes` larger than 1 MiB is ignored as a whole, and a line
  of 2 048 bytes or more is ignored (as Git does), each with a warning. A
  symlinked `.veilattributes` is never followed. One you cannot read (sealed
  for a scope you are not in) counts as absent: you get the bytes as
  recorded, members get them converted, and neither is an edit.
* A merge reads `.veilattributes` as the merged file's readers can: a
  **public** file merges only under public attributes (a sealed
  `.veilattributes` counts as its last public version, or as absent), so
  a sealed `merge=union` never decides public content, and you and
  someone without the key merge the same files alike. A file cloaked for
  `team` also follows `team`'s own sealed `.veilattributes`.
