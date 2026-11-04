<!-- Written by hand (not generated). crates/vl/tests/serve_cli.rs checks that
     every method and every field of every schema below is documented here. -->

# `vl serve --local` protocol (JSON-RPC 2.0)

[`vl serve --local`](serve.md) serves one repository on a Unix socket,
`.veil/local/sock`, to editors, agents and scripts that would otherwise start
one `vl` process per question. The [guide](../guide/editors-and-agents.md)
shows it in use; this page is the contract.

```sh
vl serve --local &                          # in the repository
vl serve --call status                      # one request, its result on stdout
vl serve --call log '{"limit": 5}'
```

## Framing

* The transport is a Unix stream socket at `<repository>/.veil/local/sock`.
* Messages are [JSON-RPC 2.0](https://www.jsonrpc.org/specification), one
  per line: each request (or batch) is one line of UTF-8 JSON ended by `\n`,
  and each response is one line. Blank lines are skipped.
* **Request:** `{"jsonrpc":"2.0","id":1,"method":"log","params":{"limit":5}}`.
  * `id` is a string, a number or `null`. A request without `id` is a
    *notification*: it is carried out, and nothing is answered.
  * `params` is an object (named parameters), or is left out. Positional
    (array) parameters are refused. An unknown parameter is an error, as an
    unknown flag is on the command line.
  * A request has no other members.
* **Response:** `{"jsonrpc":"2.0","id":1,"result":{…}}` or
  `{"jsonrpc":"2.0","id":1,"error":{"code":…,"message":…,"data":…}}`.
* **Batch:** a JSON array of up to 64 requests, answered by one array, on one
  line, of the responses to those that are not notifications. Requests in a
  batch run one after another.
* Requests on one connection are answered in order. Open more connections to
  run requests at the same time.
* Strings are escaped as in `--json` output: besides what JSON escapes, DEL,
  the C1 controls and the Unicode bidirectional overrides are written as
  `\uXXXX`. A decoder gives back the raw string; escape it yourself before
  showing it to a person.

## Methods

Each read method answers with exactly the document its command prints with
`--json`, byte for byte (the same code builds and serialises it); the schemas
are in the [JSON reference](json.md). The write methods answer with the
documents described [below](#write-results).

| Method | Command | Parameters | Result |
|---|---|---|---|
| `status` | `vl status` | | [`veil.status/1`](json.md#veilstatus1) |
| `log` | `vl log` | `limit` (number) | [`veil.log/1`](json.md#veillog1) |
| `diff` | `vl diff` | `rev`, or `from` and `to` (revisions); `stat` (bool) | [`veil.diff/1`](json.md#veildiff1) |
| `show` | `vl show` | `rev` (default `@`), `stat` (bool) | [`veil.show/1`](json.md#veilshow1) |
| `ws.list` (also `workspace.list`) | `vl workspace list` | | [`veil.workspace.list/1`](json.md#veilworkspacelist1) |
| `tag.list` | `vl tag list` | | [`veil.tag.list/1`](json.md#veiltaglist1) |
| `op.log` | `vl op log` | `limit` (number, default 20) | [`veil.op.log/1`](json.md#veiloplog1) |
| `scan` | `vl scan` | `policy_from` (a file inside the repository) | [`veil.scan/1`](json.md#veilscan1) |
| `secret.list` | `vl secret list` | | [`veil.secret.list/1`](json.md#veilsecretlist1) |
| `snapshot` | (any command's automatic snapshot) | none | [`veil.snapshot/1`](#veilsnapshot1) |
| `describe` | `vl describe` | `message` (required), `rev` (default `@`) | [`veil.describe/1`](#veildescribe1) |
| `new` | `vl new` | `revs` (list, default `[@]`), `message` | [`veil.new/1`](#veilnew1) |
| `commit` | `vl commit` | `message` (required), `no_advance` (bool) | [`veil.commit/1`](#veilcommit1) |
| `split` | `vl split` | `files` (required: a [plan](json.md#veilsplit1)'s `files`), `rev` (default `@`), `message` | [`veil.split/1`](json.md#veilsplit1) |
| `squash` | `vl squash` | `rev` (default `@`), `into` (a revision), `files` (as for `split`; leave it out to move the whole change) | [`veil.squash/1`](json.md#veilsquash1) |
| `watch` | | `interval_ms` (50–60000, default 500), `working_copy` (bool) | [`veil.watch/1`](#veilwatch1), then [`changed`](#notifications) notifications |
| `unwatch` | | none | [`veil.watch/1`](#veilwatch1) |
| `server.info` | | none | [`veil.server.info/1`](#veilserverinfo1) |

Parameters are named after the command's long flags, in `snake_case`
(`--no-advance` is `no_advance`; `vl log -n` is `limit`), and positional
arguments after their placeholder (`vl show REV` is `rev`). Revisions are
everything the command line accepts (`@`, `@-`, `main`, change and snapshot
id prefixes, `root()`).

**`snapshot`** (bool): every method except `snapshot`, `watch`, `unwatch`,
`server.info` and a `policy_from` scan takes it. As every `vl` command does,
a request first records the working copy as a snapshot of `@` (`true`, the
default), then answers, then brings the working copy in line with the
repository if the request moved it. `false` is `vl --no-snapshot`, with one
difference: such a request also never writes to the working copy, so a read
with `"snapshot": false` changes nothing at all. A server started as
`vl --no-snapshot serve --local` defaults to `false`.

**`policy_from`** (`scan`): the CI gate of `vl scan --policy-from`, with
the rules taken from that file. It must name a file inside the repository
(relative to its root, or absolute) and not under `.veil/`; symbolic links
are resolved first. The gate never snapshots, so `snapshot` is refused with
it.

### Write results

The write methods are the commands: they call the same functions, take the
repository lock exactly as the command does (for each transaction, never
between requests), and record the same operations, so `vl undo` and
`vl op restore` take them back. `operation` in each result is the head of
the operation log afterwards.

#### `veil.snapshot/1`

The working copy was recorded (if nothing changed, no operation was).

| Field | Type | |
|---|---|---|
| `schema` | string | `veil.snapshot/1` |
| `working_copy` | [snapshot reference](json.md#snapshot-reference) | the working-copy snapshot now |
| `operation` | [operation](#operation) | the head of the operation log |

#### `veil.describe/1`

| Field | Type | |
|---|---|---|
| `schema` | string | `veil.describe/1` |
| `described` | [snapshot reference](json.md#snapshot-reference) | the change with its new description (a new snapshot of it; descendants are rebased onto it) |
| `operation` | [operation](#operation) | |

#### `veil.new/1`

| Field | Type | |
|---|---|---|
| `schema` | string | `veil.new/1` |
| `working_copy` | [snapshot reference](json.md#snapshot-reference) | the new change, now the working copy |
| `operation` | [operation](#operation) | |

#### `veil.commit/1`

| Field | Type | |
|---|---|---|
| `schema` | string | `veil.commit/1` |
| `committed` | [snapshot reference](json.md#snapshot-reference) | the change just committed |
| `working_copy` | [snapshot reference](json.md#snapshot-reference) | the new, empty change on top of it |
| `advanced` | list of strings | tags that moved from the parent to the committed change |
| `kept` | list of objects | tags at the parent that stayed: `name`; `reason`, `cloaked_line` (a commit on a line cloaked for `scope` never moves an uncloaked tag) or `no_advance`; `scope` (null for `no_advance`) |
| `operation` | [operation](#operation) | |

#### Operation

`{"op_id": "<64 hex digits>", "op_short": "<8>"}`: an operation of
[`vl op log`](op.md#vl-op-log).

### Other results

#### `veil.server.info/1`

| Field | Type | |
|---|---|---|
| `schema` | string | `veil.server.info/1` |
| `version` | string | the server's `vl --version` line |
| `root` | string | the repository's root directory |
| `socket` | string | the socket's path |
| `pid` | number | the server's process id |
| `methods` | list of strings | every method name |
| `max_request_bytes` | number | the largest request line (1 MiB) |
| `max_connections` | number | clients served at once (32) |
| `max_batch` | number | requests in a batch (64) |

#### `veil.watch/1`

| Field | Type | |
|---|---|---|
| `schema` | string | `veil.watch/1` |
| `watching` | bool | true after `watch`, false after `unwatch` |
| `operation` | [operation](#operation) or null | the head of the operation log when watching started (null after `unwatch`) |
| `interval_ms` | number or null | how often the server looks |
| `working_copy` | bool | whether the server also snapshots the working copy |

## Notifications

After `watch`, the server sends a notification on that connection whenever
the head of the operation log moves, whoever moved it: a `vl` command, a
request on another connection, `vl watch`, a pull.

```json
{"jsonrpc":"2.0","method":"changed","params":{"schema":"veil.changed/1","operation":{"op_id":"f16115ae…","op_short":"f16115ae","timestamp":"2026-11-04T10:01:43.424Z","user":"alice","description":"describe change pyzuyqlq"}}}
```

#### `veil.changed/1`

| Field | Type | |
|---|---|---|
| `schema` | string | `veil.changed/1` |
| `operation` | object | the new head, as [`veil.op.log/1`](json.md#veiloplog1) lists operations: `op_id`, `op_short`, `timestamp`, `user`, `description` |

Several operations in one interval give one notification, for the newest.
React by asking again (`status`, `log`): a notification says *that*
something changed, not what.

Edits on disk become an operation only when something records them. With
`"working_copy": true` the server does, every interval, as
[`vl watch`](watch.md) does: an edit then causes a snapshot, which causes a
notification. Without it, edits are noticed at the next command or request
that snapshots. The server never watches the filesystem itself (no inotify,
no FSEvents); that, and push notifications per working-copy file, are future
work.

`watch` again replaces the subscription; `unwatch`, or closing the
connection, ends it. Responses and notifications on a connection never
interleave within a line.

## Errors

| Code | Meaning |
|---|---|
| -32700 | Parse error: the line is not one JSON value in UTF-8 (also: nested too deeply) |
| -32600 | Invalid request: not a request object, `jsonrpc` is not `"2.0"`, `method` not a string, a bad `id`, an unknown member, an empty or too large batch, or a line over 1 MiB or not finished within 30 seconds (in these two cases the server then closes the connection) |
| -32601 | No such method |
| -32602 | Invalid parameters: positional parameters, an unknown or mistyped parameter, a missing required one, `rev` together with `from`/`to`, a `policy_from` outside the repository, a string holding a NUL character (no command-line argument can) |
| -32603 | Internal error (a bug; the server keeps running and logs it on its standard error) |
| -32000 | The command failed. `message` is what `vl` prints after `error:`, and `data` is its [`veil.error/1`](json.md#veilerror1) document |
| -32001 | Too many clients: sent instead of serving the connection, which is then closed |

```json
{"jsonrpc":"2.0","id":3,"error":{"code":-32000,"message":"revision 'nope' not found","data":{"schema":"veil.error/1","error":{"message":"revision 'nope' not found","hint":null}}}}
```

## Concurrency and freshness

* Every request opens the repository afresh, exactly as a `vl` process does.
  Nothing is cached between requests, so an answer always reflects every
  command that finished before it, from any process.
* The repository lock is held only inside a request's transactions, as by
  the command. `vl` commands run while the server is up, and the server
  waits for them as one `vl` waits for another.
* Requests that touch the working copy (a snapshot, a write) run one at a
  time within the server; reads with `"snapshot": false` run in parallel.
* Warnings a command would print (a quarantined file, a skipped path) go to
  the server's standard error. The documents carry the same facts
  (`quarantined`, `redacted`, …).

## Security

* **Only you can connect.** `.veil/local` is made `0700` and must belong to
  you and not be a symbolic link; the socket is created `0600`. Each
  connection's peer credentials (`SO_PEERCRED` on Linux, `getpeereid` on
  macOS) must name the user running the server; any other connection is
  closed unanswered. `vl serve --call` checks the server's credentials the
  same way before it sends anything.
* **Nothing more than the CLI shows.** The server answers with the identity
  of the user who started it (`VEIL_HOME`, `VEIL_USER` of its environment),
  through the same code as the commands: content you hold no key for is
  redacted, sealed descriptions are hidden, secret values never appear. See
  [Confidentiality](json.md#confidentiality).
* **Nothing outside the repository.** No parameter names a path except
  `policy_from`, which must lie inside the repository. There is no method
  that runs a program (`vl run`, `vl ws exec` are not served).
* **Limits:** a request line is at most 1 MiB; at most 32 clients at once; a
  client that does not read its answers for 60 seconds is disconnected.
* **Timeouts:** a connection that sends no request within 30 seconds is
  closed, and so is one whose request line is not complete 30 seconds after
  its first byte (answered with `-32600` first). Between requests a client
  may stay quiet as long as it likes, unless the server is full: then a new
  client takes the slot of the connection that has been quiet longest, if
  that is at least 10 seconds and it is not subscribed to `watch`, and that
  connection is closed. A client that keeps a connection open should
  reconnect when it is closed. (`VEIL_SERVE_IDLE_MS`,
  `VEIL_SERVE_REQUEST_MS` and `VEIL_SERVE_EVICT_MS` in the server's
  environment set the three durations, in milliseconds, for tests.)
* **Strings** in the parameters cannot hold a NUL character, as no
  command-line argument can.

## Lifetime

* One server per repository: a second `vl serve --local` refuses to start
  while the first runs (it holds a lock on `.veil/local/serve.lock`).
* A socket left by a server that died is stale: the next server replaces it.
  Anything at that path that is not a socket is left alone, and the server
  refuses to start.
* On SIGINT (Ctrl-C), SIGTERM or SIGHUP the server stops accepting, removes
  its socket, lets requests in flight finish (up to 30 seconds) and exits 0.
  If its socket is removed, moved or replaced underneath it, it exits too.
* The server serves the repository it started in, not a path. If the
  repository is moved or renamed, or another one is put in its place
  (`.veil` included), the server refuses the next request with `-32000`
  ("… was moved or replaced …"), stops within a second, and removes its
  socket. Start it again where the repository is now.

## `vl serve --call`

`vl serve --call METHOD [PARAMS]` sends one request, with `PARAMS` as a JSON
object, to the server of the repository found as for every command (`-R`, or
upward from the current directory), and prints the result, exactly as the
server sent it, on one line. For `watch` it then prints the params of every
notification, one per line, until interrupted. On an error response it
prints the `veil.error/1` document on standard output, the message on
standard error, and exits 1. Like `vl scan`, it also exits 1 when a `scan`
result is not `clean`.
