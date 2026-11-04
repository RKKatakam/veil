# Editors and agents: `vl serve --local`

An editor that shows the status of your files, or an AI agent that checks
the log after every step, asks Veil the same questions hundreds of times.
Starting a `vl` process for each works (see [Scripting with
`--json`](scripting.md)), but `vl serve --local` lets such a tool keep one
connection open instead. It serves the repository on a Unix socket that
only you can reach, in [JSON-RPC 2.0](../reference/json-rpc.md), and every
answer is exactly the document the matching `vl … --json` command prints.

## Start the server

In the repository (or with `-R PATH`):

```sh
vl serve --local
```

```text
note: /home/alice/demo/.veil/local is now private (mode 0700)
Serving /home/alice/demo on /home/alice/demo/.veil/local/sock (JSON-RPC 2.0, one request per line; Ctrl-C to stop)
```

The server runs in the foreground until you press Ctrl-C (or send it
SIGTERM); it then removes its socket. Run it in a terminal tab, under your
editor's process manager, or in the background (`vl serve --local &`). Only
one server runs per repository: a second one says which process is already
serving. If a server was killed, the next one replaces the socket it left.

`vl` commands keep working as usual while the server runs, in the same
directory and at the same time. The server reads the repository afresh for
every request, so it never answers from a stale view. If you move or rename
the repository, the server stops (it never serves whatever is at the old
path); start it again in the new place.

## Try it from the shell

`vl serve --call METHOD [PARAMS]` sends one request and prints the result:

```sh
vl serve --call status
```

```text
{"schema":"veil.status/1","workspace":{"name":"default","cloak":null},"working_copy":{"snapshot_id":"e3424b1b…","snapshot_short":"e3424b1b","change_id":"ltlptpvm…","change_short":"ltlptpvm","available":true,"empty":false,"description":"","description_hidden":null},"parents":[…],"changes":[{"path":"main.rs","status":"added","visibility":{"kind":"public","scope":null,"embargo":null},"redacted":false}],"isolated":[],"quarantined":[],"policy_held_back":[],"nested":[],"redacted":[],"conflicts":[]}
```

Parameters are a JSON object named after the command's flags:

```sh
vl serve --call log '{"limit":5}'
vl serve --call diff '{"from":"main","stat":true}'
vl serve --call show '{"rev":"@-"}'
```

and it pipes into `jq` like `--json` does:

```sh
vl serve --call status | jq -r '.changes[] | "\(.status) \(.path)"'
```

```text
added main.rs
```

## Record work

Six methods change the repository, exactly as their commands do:
`snapshot` (record the working copy now), `describe`, `new`, `commit`,
`split` and `squash`. The last two take what to move as a list of files,
each with the hunks to take (`vl diff --json` numbers them) or none for the
whole file; there is no picker over the socket:

```sh
vl serve --call split '{"files":[{"path":"src/config.rs","hunks":[1,3]}],"message":"Config: read the new keys"}'
```

```sh
vl serve --call commit '{"message":"Add main.rs"}'
```

```text
{"schema":"veil.commit/1","committed":{"snapshot_id":"39a14714…","snapshot_short":"39a14714","change_id":"ltlptpvm…","change_short":"ltlptpvm","available":true,"empty":false,"description":"Add main.rs","description_hidden":null},"working_copy":{…,"empty":true,…},"advanced":["main"],"kept":[],"operation":{"op_id":"380df4fe…","op_short":"380df4fe"}}
```

They take the repository lock and record operations like the commands, so
`vl undo` takes back a commit made by an agent just as it takes back yours:

```sh
vl undo
```

As with every `vl` command, each request first snapshots the working copy.
For a read that should change nothing at all, pass `"snapshot": false`:

```sh
vl serve --call log '{"limit":20,"snapshot":false}'
```

## Be told when something changes

Instead of polling, subscribe with `watch`. The server then sends a
`changed` notification on that connection whenever the operation log moves,
whether you ran a command, another client wrote, or `vl pull` brought
something in:

```sh
vl serve --call watch
```

```text
{"schema":"veil.watch/1","watching":true,"operation":{"op_id":"ed7c1fa4…","op_short":"ed7c1fa4"},"interval_ms":500,"working_copy":false}
{"schema":"veil.changed/1","operation":{"op_id":"f16115ae…","op_short":"f16115ae","timestamp":"2026-11-04T10:01:43.424Z","user":"alice","description":"describe change pyzuyqlq"}}
```

(That second line appeared when `vl describe -m "Start the next change"`
ran in another terminal.) A notification only says that something changed;
ask again (`status`, `log`) to see what.

Edits you save in the editor are not operations until something records
them. With `{"working_copy":true}` the server snapshots the directory every
interval, as [`vl watch`](../reference/watch.md) does, so a saved file
causes a notification within half a second.

## From a program

Any language with Unix sockets and JSON can talk to the server. Write one
request per line and read one response per line. In Python:

```python
import json, socket

s = socket.socket(socket.AF_UNIX)
s.connect(".veil/local/sock")          # relative to the repository root
f = s.makefile("rwb")

def call(method, **params):
    f.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode() + b"\n")
    f.flush()
    reply = json.loads(f.readline())
    if "error" in reply:
        raise RuntimeError(reply["error"]["message"])
    return reply["result"]

for change in call("status")["changes"]:
    print(change["status"], change["path"])
print(call("log", limit=1, snapshot=False)["entries"][0]["description"])
```

Node.js has `net.createConnection(".veil/local/sock")` and a line reader,
and any LSP-style client that speaks newline-delimited JSON-RPC works
unchanged. A failing command answers with error code `-32000`, its message,
and the same `veil.error/1` document `--json` prints, as `data`:

```text
{"jsonrpc":"2.0","id":3,"error":{"code":-32000,"message":"revision 'nope' not found","data":{"schema":"veil.error/1","error":{"message":"revision 'nope' not found","hint":null}}}}
```

The [protocol reference](../reference/json-rpc.md) lists every method, its
parameters and results, and the error codes.

## What the server will not do

* **Show more than `vl` would.** It answers as the user who started it,
  through the same code as the commands: cloaked content you hold no key
  for is redacted, sealed descriptions are hidden, secret values never
  appear. See [Secrets and visibility](secrets-and-visibility.md).
* **Let anyone else in.** The socket is `0600` in a `0700` directory, and the
  server checks every client's user id with the kernel (peer credentials).
  Another user on the machine cannot connect, even if they could reach the
  file.
* **Touch anything outside the repository.** No method takes a path except
  `scan`'s `policy_from`, which must be a file in the repository, and no
  method runs a program (`vl run` and `vl ws exec` are not served).
* **Listen on the network.** It is a Unix socket; there is no TCP mode.

Requests are limited to 1 MiB, and to 32 clients at once. A connection
must send its first request within 30 seconds; after that it may stay open
and quiet, but when all 32 slots are taken, the connection quiet longest
(10 seconds or more, and not watching) is closed to let a new client in, so
a client that keeps its connection should reconnect when it is closed.

---

[User guide](README.md) · [Protocol reference](../reference/json-rpc.md) · [`vl serve`](../reference/serve.md)
