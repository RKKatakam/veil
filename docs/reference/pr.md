<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl pr`

PRs and review on the Veil server: a PR is visible only to people who can see every file it touches; reviews are signed by this device and stop counting when the files change

Subcommands:

* [`vl pr create`](#vl-pr-create): Open a PR for the stack of changes from the target's tip to REV (pushed first, with `vl push`)
* [`vl pr list`](#vl-pr-list): List the PRs you may see (open ones by default)
* [`vl pr show`](#vl-pr-show): Show a PR: its revisions, review and threads
* [`vl pr diff`](#vl-pr-diff): Show a PR's diff (the current revision's, or one change's)
* [`vl pr update`](#vl-pr-update): Make a new revision of a PR from REV (its changes keep their change ids; pushed first)
* [`vl pr comment`](#vl-pr-comment): Comment on a PR, on lines of a file it changes, or in a thread
* [`vl pr resolve`](#vl-pr-resolve): Resolve a thread (or reopen it)
* [`vl pr review`](#vl-pr-review): Approve the PR's current revision, or ask for changes
* [`vl pr dismiss`](#vl-pr-dismiss): Dismiss a reviewer's request for changes (admins): the only way it stops holding the PR but that reviewer's own approval
* [`vl pr close`](#vl-pr-close): Close a PR (its author or an admin)
* [`vl pr land`](#vl-pr-land): Land a PR whose review rules are met

## `vl pr create`

Open a PR for the stack of changes from the target's tip to REV (pushed first, with `vl push`)

```text
vl pr create [OPTIONS] --title <TITLE> <REV>
```

Arguments:

| | |
|---|---|
| `<REV>` | The top change of the stack (required) |

Options:

| | |
|---|---|
| `--onto <ONTO>` | The branch it is for (default: the project's default branch) |
| `--title <TITLE>` | (required) |
| `--body <BODY>` |  |
| `--json` | Print one JSON document instead of text (its schema is named in its `schema` field; see docs/reference/json.md). Errors then also print a `veil.error/1` document |

## `vl pr list`

List the PRs you may see (open ones by default)

```text
vl pr list [OPTIONS]
```

Options:

| | |
|---|---|
| `--state <STATE>` | open, closed, landed or all |
| `--all` | Every state |
| `--search <SEARCH>` | Only PRs whose title or body holds this text |
| `--json` | Print one JSON document instead of text (its schema is named in its `schema` field; see docs/reference/json.md). Errors then also print a `veil.error/1` document |

## `vl pr show`

Show a PR: its revisions, review and threads

```text
vl pr show [OPTIONS] <ID>
```

Arguments:

| | |
|---|---|
| `<ID>` | (required) |

Options:

| | |
|---|---|
| `--threads` | Also show its threads and comments |
| `--json` | Print one JSON document instead of text (its schema is named in its `schema` field; see docs/reference/json.md). Errors then also print a `veil.error/1` document |

## `vl pr diff`

Show a PR's diff (the current revision's, or one change's)

```text
vl pr diff [OPTIONS] <ID>
```

Arguments:

| | |
|---|---|
| `<ID>` | (required) |

Options:

| | |
|---|---|
| `--revision <REVISION>` |  |
| `--change <CHANGE>` | One change of the stack (its change id) |
| `--stat` | Only list changed paths |
| `--json` | Print one JSON document instead of text (its schema is named in its `schema` field; see docs/reference/json.md). Errors then also print a `veil.error/1` document |

## `vl pr update`

Make a new revision of a PR from REV (its changes keep their change ids; pushed first)

```text
vl pr update [OPTIONS] <ID> <REV>
```

Arguments:

| | |
|---|---|
| `<ID>` | (required) |
| `<REV>` | (required) |

Options:

| | |
|---|---|
| `--json` | Print one JSON document instead of text (its schema is named in its `schema` field; see docs/reference/json.md). Errors then also print a `veil.error/1` document |

## `vl pr comment`

Comment on a PR, on lines of a file it changes, or in a thread

```text
vl pr comment [OPTIONS] --message <MESSAGE> <ID>
```

Arguments:

| | |
|---|---|
| `<ID>` | (required) |

Options:

| | |
|---|---|
| `-m, --message <MESSAGE>` | (required) |
| `--path <PATH>` | A file the PR changes |
| `--line <LINE>` | The (first) line, 1-based |
| `--end <END>` | The last line (default: --line) |
| `--old` | Lines of the version before the change |
| `--change <CHANGE>` | The change of the stack (default: the top one that changes the file) |
| `--thread <THREAD>` | Reply in this thread instead |
| `--json` | Print one JSON document instead of text (its schema is named in its `schema` field; see docs/reference/json.md). Errors then also print a `veil.error/1` document |

## `vl pr resolve`

Resolve a thread (or reopen it)

```text
vl pr resolve [OPTIONS] <ID> <THREAD>
```

Arguments:

| | |
|---|---|
| `<ID>` | (required) |
| `<THREAD>` | (required) |

Options:

| | |
|---|---|
| `--reopen` |  |

## `vl pr review`

Approve the PR's current revision, or ask for changes

```text
vl pr review [OPTIONS] <ID>
```

Arguments:

| | |
|---|---|
| `<ID>` | (required) |

Options:

| | |
|---|---|
| `--approve` |  |
| `--request-changes` |  |
| `-m, --message <MESSAGE>` |  |
| `--json` | Print one JSON document instead of text (its schema is named in its `schema` field; see docs/reference/json.md). Errors then also print a `veil.error/1` document |

## `vl pr dismiss`

Dismiss a reviewer's request for changes (admins): the only way it stops holding the PR but that reviewer's own approval

```text
vl pr dismiss [OPTIONS] <ID> <PERSON>
```

Arguments:

| | |
|---|---|
| `<ID>` | (required) |
| `<PERSON>` | (required) |

## `vl pr close`

Close a PR (its author or an admin)

```text
vl pr close [OPTIONS] <ID>
```

Arguments:

| | |
|---|---|
| `<ID>` | (required) |

## `vl pr land`

Land a PR whose review rules are met

```text
vl pr land [OPTIONS] <ID>
```

Arguments:

| | |
|---|---|
| `<ID>` | (required) |

---

[All commands](README.md) · [User guide](../guide/README.md)
