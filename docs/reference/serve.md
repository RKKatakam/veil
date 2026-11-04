<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl serve`

Serve this repository to editors and agents over a local socket.

`vl serve --local` listens on `.veil/local/sock`, a Unix socket only you can connect to, and answers newline-delimited JSON-RPC 2.0: one request per line, one response per line. The read methods (`status`, `log`, `diff`, `show`, `ws.list`, `tag.list`, `op.log`, `scan`, `secret.list`) answer with exactly the document their command prints with `--json`; `snapshot`, `describe`, `new` and `commit` record operations as the commands do (`vl undo` takes them back); `watch` sends a notification whenever the operation log moves. The repository is read afresh for every request, and its lock is taken only while a request writes. Stop it with Ctrl-C or SIGTERM: the socket is removed. See docs/reference/json-rpc.md.

```text
vl serve [OPTIONS] [PARAMS]
```

Arguments:

| | |
|---|---|
| `<PARAMS>` | The request's parameters with `--call`: a JSON object, e.g. '{"limit": 5}' |

Options:

| | |
|---|---|
| `--local` | Listen on the repository's local socket |
| `--call <METHOD>` | Client: send one request to the running server and print its result (for `watch`, then every notification, one per line) |

---

[All commands](README.md) · [User guide](../guide/README.md)
