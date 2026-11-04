# Scripting with `--json`

Editors, CI jobs, agents and shell scripts should not parse `vl`'s text
output: it is written for people and may change. The read commands take
`--json` and print one JSON document instead, with a versioned schema:

| Command | Prints |
|---|---|
| `vl status --json` | the working-copy change, its changes, local-only, quarantined and redacted files, conflicts |
| `vl log --json` | the snapshot graph, with tags, workspaces, signatures and parents |
| `vl diff --json`, `vl show --json` | changed files as structured hunks |
| `vl workspace list --json`, `vl tag list --json` | workspaces and tags, with the snapshot each points at |
| `vl op log --json` | the operation log |
| `vl scan --json` | secret-scan findings, also as a CI gate (`--policy-from`) |
| `vl secret list --json` | the names in the local vault (never the values) |
| `vl resolve --list --json` | unresolved conflicts, each version with who can read it (never content) |

Every field is documented in the [JSON reference](../reference/json.md).

A tool that asks many questions (an editor, an agent) can keep one
connection open instead of starting `vl` each time: [`vl serve
--local`](editors-and-agents.md) answers with the same documents.

## Examples

Conflicted files, and whether you can resolve each one:

```sh
vl resolve --list --json | jq -r '.conflicts[] | "\(.path) \(if .conflict.unreadable_side then "(needs a member)" else "" end)"'
```

Changed files, one per line:

```sh
vl status --json | jq -r '.changes[] | "\(.status) \(.path)"'
```

```text
modified README.md
```

The log, without the root:

```sh
vl log --json | jq -r '.entries[] | select(.root | not) | "\(.change_short) \(.description)"'
```

```text
kxqpvmkk 
pqmvvlvm Add the README
```

The other flags work as usual:

```sh
vl diff --stat --json | jq -c '.files[] | {path, status}'
```

```text
{"path":"README.md","status":"modified"}
```

```sh
vl secret list --json
```

```text
{"schema":"veil.secret.list/1","secrets":[{"name":"DB_PASSWORD"}]}
```

## What a script can rely on

* **One document, one line**, on standard output. Warnings and errors still
  go to standard error.
* **`schema`** names the document and its version: `veil.status/1`. New
  fields may appear without notice; anything that could break a reader (a
  field removed, renamed or retyped) comes with a new version,
  `veil.status/2`. Check `schema`, and ignore fields you don't know.
* **The same exit status** as without `--json`. When a command fails, its
  document is a `veil.error/1` instead:

  ```sh
  vl show nosuch --json
  ```

  ```text
  {"schema":"veil.error/1","error":{"message":"revision 'nosuch' not found","hint":null}}
  ```

  Usage errors (a misspelt flag) are the exception: exit status 2, text on
  standard error, nothing on standard output.
* **Raw strings.** The text output escapes control characters in names,
  descriptions and file content; JSON gives you the original strings, so
  escape them before you show them to a person.

## Nothing more than the text shows

`--json` never shows a reader more than the text output does. Content you
cannot decrypt appears as a redaction with a reason (`no_key`, `withheld`,
`not_released`), never as content; a description sealed for a scope you are
not in is `null`, with the scope named in `description_hidden`. Isolated
files are listed by path only, and `vl secret list` lists names only. See
[Secrets and visibility](secrets-and-visibility.md) for what each tier
protects.

---

[User guide](README.md) · [JSON reference](../reference/json.md) · Next: [Editors and agents](editors-and-agents.md)
