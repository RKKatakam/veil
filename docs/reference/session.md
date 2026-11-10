<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl session`

Sessions on the project's server for agents (`vl session agent`)

Subcommands:

* [`vl session agent`](#vl-session-agent): Make an agent session on the project's server (origin), for a harness, and print it as JSON
* [`vl session ci`](#vl-session-ci): Make a CI runner session on the project's server (origin), and print it as JSON

## `vl session agent`

Make an agent session on the project's server (origin), for a harness, and print it as JSON.

The session is made from yours: it lasts at most 12 hours (never past your own session), sees at most what you see in this project, and with --only less (files are read and written only at or below those paths; history is yours). Commits through the API with it carry its attribution, which the server stamps. Nobody stores or rotates it: make a new one per run. An agent session cannot change access, devices, invites, key rings or shares, nor make sessions.

```text
vl session agent [OPTIONS]
```

Options:

| | |
|---|---|
| `--only <PATH>` | Narrow the session to these folders or files (from the project root) |
| `--agent <AGENT>` | Record the run as made by this agent (e.g. "claude-code opus-5.5"); also $VEIL_AGENT |
| `--task <TASK>` | The agent's task: an id or title (with --agent); also $VEIL_AGENT_TASK |
| `--prompt-ref <REF>` | A reference to the agent's prompt: a URL, transcript id or digest (with --agent); also $VEIL_AGENT_PROMPT_REF |
| `--run <ID>` | The harness's run or session id (with --agent); also $VEIL_AGENT_RUN |

## `vl session ci`

Make a CI runner session on the project's server (origin), and print it as JSON.

A runner session reads only what its grant allows (narrowed by `--only` or `[checks.<name>].paths` in `.veilrules`) and writes only CI check results (`POST /v1/projects/{p}/checks`); it cannot upload objects, push, create changes, or land anything.

```text
vl session ci [OPTIONS]
```

Options:

| | |
|---|---|
| `--check <CHECK>` | Check name (`ci/build`, `ci/test`); when `--only` is omitted, narrows to `[checks.<name>].paths` from `.veilrules` |
| `--only <PATH>` | Narrow the session to these folders or files (from the project root) |
| `--agent <AGENT>` | Record the run as made by this agent (e.g. "claude-code opus-5.5"); also $VEIL_AGENT |
| `--task <TASK>` | The agent's task: an id or title (with --agent); also $VEIL_AGENT_TASK |
| `--prompt-ref <REF>` | A reference to the agent's prompt: a URL, transcript id or digest (with --agent); also $VEIL_AGENT_PROMPT_REF |
| `--run <ID>` | The harness's run or session id (with --agent); also $VEIL_AGENT_RUN |

---

[All commands](README.md) · [User guide](../guide/README.md)
