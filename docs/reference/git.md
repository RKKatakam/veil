<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl git`

Two-way Git interop: import Git history, push and fetch Git remotes.

Git sees exactly what a public Veil remote sees: no cloaked or isolated files, no cloaked descriptions, and the pre-merge tree of an unreleased embargo. Tags map to branches.

Subcommands:

* [`vl git import`](#vl-git-import): Import a Git repository's history (path or URL): adds it as a Git remote and creates a tag for every branch
* [`vl git remote`](#vl-git-remote): Manage Git remotes
* [`vl git fetch`](#vl-git-fetch): Fetch a Git remote's branches as `<remote>/<branch>` (local tags stay)
* [`vl git pull`](#vl-git-pull): Fetch, then create or fast-forward local tags from the branches
* [`vl git push`](#vl-git-push): Export tags (all by default) as branches and push them
* [`vl git export`](#vl-git-export): Export tags into the local bridge repository without pushing, and print the commit of each

## `vl git import`

Import a Git repository's history (path or URL): adds it as a Git remote and creates a tag for every branch

```text
vl git import [OPTIONS] <SOURCE>
```

Arguments:

| | |
|---|---|
| `<SOURCE>` | Git repository: a path or any URL `git` understands (required) |

Options:

| | |
|---|---|
| `--remote <REMOTE>` | Name of the Git remote to create (default: `origin`) |

## `vl git remote`

Manage Git remotes

Subcommands:

* [`vl git remote add`](#vl-git-remote-add): Add a Git remote (any URL `git` understands, or a path)
* [`vl git remote list`](#vl-git-remote-list): List Git remotes
* [`vl git remote rm`](#vl-git-remote-rm): Remove a Git remote

### `vl git remote add`

Add a Git remote (any URL `git` understands, or a path)

```text
vl git remote add [OPTIONS] <NAME> <URL>
```

Arguments:

| | |
|---|---|
| `<NAME>` | Git remote name (required) |
| `<URL>` | Any URL `git` understands, or a path (required) |

### `vl git remote list`

List Git remotes

```text
vl git remote list [OPTIONS]
```

### `vl git remote rm`

Remove a Git remote

```text
vl git remote rm [OPTIONS] <NAME>
```

Arguments:

| | |
|---|---|
| `<NAME>` | Git remote name (required) |

## `vl git fetch`

Fetch a Git remote's branches as `<remote>/<branch>` (local tags stay)

```text
vl git fetch [OPTIONS] [REMOTE]
```

Arguments:

| | |
|---|---|
| `<REMOTE>` | Git remote (default: `origin`) |

## `vl git pull`

Fetch, then create or fast-forward local tags from the branches

```text
vl git pull [OPTIONS] [REMOTE]
```

Arguments:

| | |
|---|---|
| `<REMOTE>` | Git remote (default: `origin`) |

## `vl git push`

Export tags (all by default) as branches and push them

```text
vl git push [OPTIONS] [REMOTE]
```

Arguments:

| | |
|---|---|
| `<REMOTE>` | Git remote (default: `origin`) |

Options:

| | |
|---|---|
| `-t, --tag <TAG>` | Only push these tags |
| `--force` | Overwrite branches that moved on the Git side (only if they still hold what was last fetched) |
| `-d, --delete <BRANCH>` | Delete this branch on the Git remote (repeatable). Delete its tag here first with `vl tag delete`. Refused if the branch moved since the last fetch (unless --force). With no --tag, nothing else is pushed |

## `vl git export`

Export tags into the local bridge repository without pushing, and print the commit of each

```text
vl git export [OPTIONS]
```

Options:

| | |
|---|---|
| `-t, --tag <TAG>` | Only export these tags |

---

[All commands](README.md) · [User guide](../guide/README.md)
