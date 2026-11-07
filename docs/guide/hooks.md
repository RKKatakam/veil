# Hooks

Hooks are commands `vl` runs at fixed points: before a commit, before a
push, after the working copy moves. Veil has Git's two kinds:

* **Your own hooks** live on your device and run without asking, like
  `.git/hooks`.
* **Hooks the repository suggests** live in a tracked file, `.veilhooks`.
  They run only after you have read them and trusted them **on this
  device**. Trust is pinned to their exact content: when a teammate changes
  them, they stop running until you trust them again.

Veil treats a teammate's push as untrusted input, so hooks follow one rule:
nothing that arrives by a pull or a merge runs until you trust it on this
device.

## Hook points

| hook | runs | told | a failure |
|---|---|---|---|
| `pre-commit` | before `vl commit`, `vl describe` of `@`, and `commit` / `describe` over `vl serve` | `VEIL_SNAPSHOT` (the `@` about to be committed), `VEIL_WORKSPACE` | refuses the commit |
| `commit-msg` | after `pre-commit` | `$1`: a file holding the message (mode `0600`, in `.veil/local/tmp/`) | refuses the commit; an edited message is used |
| `pre-push` | before `vl push` to the Veil server | argv: remote name, the project's server URL; stdin: one line per tag (below) | refuses the push |
| `post-checkout` | after `vl new`, `vl edit` and `vl ws switch` moved the working copy | argv: the old and the new snapshot id | a warning only |

A hook runs in the project directory, with `VEIL_HOOK` set to its name.
`--no-verify` on `commit`, `describe` and `push` (or
`"no_verify": true` over `vl serve`) skips every hook for that command.

## Your own hooks

Put an executable at `.veil/hooks/<name>` (this repository) or
`$VEIL_HOME/hooks/<name>` (every repository; `~/.config/veil/hooks/` by
default). Both run, global first. `.veil` is never recorded, and nothing a
pull brings can write there.

```console
$ cat .veil/hooks/pre-commit
#!/bin/sh
exec cargo fmt --check
$ chmod +x .veil/hooks/pre-commit
```

A hook that is not executable is skipped with a warning.

## Hooks the repository suggests: `.veilhooks`

`.veilhooks` is a TOML file in the project root. Each hook is a table with
a `run` argv: an array, never a shell string. Several commands for one
hook are an array of tables, `[[pre-push]]`.

```toml
[pre-commit]
run = ["sh", "scripts/lint.sh"]

[pre-push]
run = ["sh", "scripts/check-push.sh"]
```

A command that reads further repository files can list them in
`files = ["scripts/common.sh"]`, so that they are pinned with it (see
below). A directory in `files` is pinned with every file below it.

Until you trust it, nothing in `.veilhooks` runs, and every command that
would run it says so:

```console
$ vl commit -m "Add hooks"
warning: .veilhooks suggests a pre-commit hook this device has not trusted; it did not run (review it with `vl hooks show`, then `vl hooks trust`)
Committed msrypqop bd64c1e5 Add hooks
Working copy now at: nrrwllkv d6addde6 (empty) (no description set)
```

### Review, then trust

`vl hooks show` lists your own hooks, each suggested command, the
repository files it runs or reads with their BLAKE3 digests, whether this
device trusts them, and the file itself:

```console
$ vl hooks show
Device-local hooks (run without asking):
  none (put executables in .veil/hooks/<name> or $VEIL_HOME/hooks/<name>)

Repository hooks: .veilhooks (blake3 2b7ec1eb…) — not trusted on this device: they do not run
  pre-commit     sh scripts/lint.sh
      scripts/lint.sh                          d8d6db4e…  not trusted
  pre-push       sh scripts/check-push.sh
      scripts/check-push.sh                    05037c7f…  not trusted

--- .veilhooks ---
[pre-commit]
run = ["sh", "scripts/lint.sh"]
…
```

Read the scripts, then trust them. `vl hooks trust` prints what it pins
and asks; off a terminal it needs `--yes`:

```console
$ vl hooks trust
Trusting .veilhooks (blake3 2b7ec1eb…):
  …
Pinned files:
  scripts/lint.sh                          d8d6db4e…
  scripts/check-push.sh                    05037c7f…
These commands will run on this device at every commit or push. Trust them? [y/N] y
Trusted .veilhooks on this device (/home/alice/proj/.veil/local/hooks-trust.json)
```

From now on they run:

```console
$ echo 'breakpoint()' >> app.py
$ vl commit -m "debug"
./app.py:2:breakpoint()
remove the breakpoint() calls first
error: the pre-commit hook `.veilhooks: sh scripts/lint.sh` failed (exit status 1); the commit was refused; fix it, or skip hooks with `--no-verify`
```

### Any change untrusts them

The trust record (`.veil/local/hooks-trust.json`) holds the digest of
`.veilhooks` and of every repository file its commands name. It is never
synced, so each teammate trusts on their own devices. When any of those
files changes (your edit, or a teammate's arriving with a pull), the hooks
stop running until you trust them again, and every command that would have
run them says what changed, and in which change:

```console
$ vl commit -m "next"
warning: .veilhooks changed since you trusted it (scripts/lint.sh, by change vxsyrpkq); its pre-commit hook did not run (review it with `vl hooks show`, then `vl hooks trust`)
Committed pxmyzlkm be3ca4a6 (empty) next
```

`vl hooks show` marks the files that changed. An argument that named no
file when you trusted the command and names one now counts as a change too
(`["python3", "lint"]` would otherwise start running a new `lint` file).

### What exactly runs

* **The bytes you trusted, and only those.** A repository file a command
  runs or is given as an argument is read once, checked against its trusted
  digest, and copied to `.veil/local/hooks-run/` (mode `0700`). The command
  gets the copy, so a script swapped after the check never runs. A script
  that finds its siblings through `$0` must name them in `files` and find
  them in the project directory instead.
* **Programs come from your system.** A bare name (`sh`, `python3`) is
  looked up on `PATH`, without its relative entries (`.`, empty) and
  without entries inside the project: a file in the repository never
  becomes a command by its name. Name repository scripts by their path
  (`scripts/lint.sh`), never by an absolute path.
* **Build tools need an explicit yes.** `make lint` runs whatever the
  `Makefile` says; `npm run lint` runs `package.json` scripts. `vl hooks
  trust` refuses such commands (make, npm, yarn, pnpm, cargo, just,
  pre-commit, gradle, pytest, eslint, `python -m` and others) unless you
  pass `--i-understand-indirect`. It then pins the tool's usual files too
  (`Makefile`, `package.json`, `.pre-commit-config.yaml`, …), so a change
  to them untrusts the hook. What those files pull in further
  (`node_modules`, an included makefile) is not pinned: trusting a build
  tool trusts the project's build. A build tool behind a launcher (`nice
  make`, `timeout 60 make`, `env A=b make`, `sudo -u ci make`, `vl run --
  npm test`) counts the same.
* **Every spelling is the same path.** `./scripts/lint.sh`,
  `scripts//lint.sh`, `--rcfile=scripts/lint.sh` and
  `LD_PRELOAD=./lib/x.so` name repository files: they are pinned, and the
  command gets the trusted copy in their place. A path `vl` cannot pin is
  refused instead: one through `..` (`x/../scripts/lint.sh`,
  `../proj/scripts/lint.sh`), an absolute one into the project or through
  `/proc`, one under `.veil` or `.git`, one glued to a short option
  (`-Iscripts/lib`: write `-I scripts/lib`), a `PATH`-like list
  (`PYTHONPATH=lib:tools`).
* **Directories.** A directory the program may run (`["python3", "tools"]`
  runs `tools/__main__.py`; `node dir` runs `dir/index.js`) is pinned with
  every file below it (at most 1024 entries and 64 MiB, no symbolic
  links), and the command gets a private copy of it. Any other directory
  (`["ruff", "check", "src"]`) is the command's input, like the project
  directory it runs in: only that it is a directory is pinned, so editing
  `src` does not untrust the hook. `.` (the project directory) is never
  pinned, and an interpreter is never given it (`["python3", "."]` is
  refused).
* **Code as text is refused.** `sh -c "make lint"`, `bash -ec …`,
  `python3 -c …`, `node -e …`, `perl -e …`, `ruby -e …`, `php -r …`, an
  `awk` program without `-f`, `env -S`, and commands that run their
  arguments through a shell or read them from their input (`xargs`,
  `watch`, `parallel`) can run repository files in a syntax `vl` does not
  read, so `vl hooks trust` refuses them, with or without
  `--i-understand-indirect`. Put the command line in a script and name the
  script.

## The environment

A hook gets a clean environment, not yours: `HOME`, `USER`, `LOGNAME`,
`LANG`, `LC_*`, `TERM`, `TMPDIR`, `TZ`, `VEIL_HOME`, `PATH` (cleaned as
above), and `VEIL_HOOK`, `VEIL_SNAPSHOT`, `VEIL_WORKSPACE`. Nothing else
from `vl`'s environment reaches it: no vault secrets (even when `vl` itself
runs under `vl run`), no `VEIL_*` or `GIT_*` variables, no tokens. A hook
that needs a secret asks for it explicitly: `run = ["vl", "run", "--",
"scripts/deploy-check.sh"]`.

A hook's stdout and stderr both go to `vl`'s stderr, so `--json` output and
`vl serve` replies never carry them. Its stdin is empty, except for
`pre-push`.

## What a hook sees

Hook input carries ids, names and the message you wrote, never file
content. A hook runs as you, in your project directory: it can read what
you can read there (that is what a linter is for), and it could run `vl
cat`. Trusting a hook means trusting it with that, so read it first.

`pre-push` reads one line per tag the push sends (or tries to, if the
server will reject it): each tag whose target differs from the server's
(`origin/<tag>`), or every such tag named with `-t`:

```text
<tag> <snapshot> <remote-snapshot-or-0>
```

## A hook cannot change what you commit

No repository lock is held while a hook runs, so a hook can run `vl
status` or `vl log`. When it is done, `vl` records the working copy again.
If the hook edited a recorded file, or ran a `vl` command that changed the
repository, the commit is refused and nothing is lost: the edits are in
`@`.

```console
$ vl commit -m "mine"
error: the repository or the working copy changed while the pre-commit hooks ran (a hook edited files or ran `vl`); nothing was lost (the edits are in @): review them and commit again
```

A formatter used as a hook therefore needs two commits, as in Git: the
first is refused with the formatted files in `@`, the second goes
through. A hook that writes a log file inside the project should write it
to an ignored path. Likewise, if a `pre-push` hook moves a tag, the push
is refused.

`vl` run from inside a hook never runs hooks itself (no recursion), and
`vl hooks trust` refuses to run there.

## Time limits and signals

A hook that runs longer than `VEIL_HOOK_TIMEOUT` seconds (default 600) is
stopped with its whole process group, and the command fails. Ctrl-C,
SIGTERM and SIGHUP reach the hook. Whatever a hook leaves running in its
process group is stopped when it exits.

## Where hooks do not run

* `vl ws exec` sandboxes and mounted workspaces never run hooks of their
  own, and `vl` inside a sandbox does not act on the project at all.
* `vl serve` runs the same hooks for `commit` and `describe` of `@`, with
  their output on the server's stderr; it has no method to trust hooks.
