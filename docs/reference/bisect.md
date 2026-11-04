<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl bisect`

Find the change that introduced a problem by binary search.

`start` checks out the first candidate (as `vl new` does); mark each one `good`, `bad` or `skip`; `reset` returns to where you started. `run` tests every candidate in a throwaway sandbox instead and never touches the working copy. The state is device-local (`.veil/local/bisect.json`).

Subcommands:

* [`vl bisect start`](#vl-bisect-start): Start a bisection between a bad and one or more good snapshots
* [`vl bisect good`](#vl-bisect-good): Mark the current candidate (or REV) good
* [`vl bisect bad`](#vl-bisect-bad): Mark the current candidate (or REV) bad
* [`vl bisect skip`](#vl-bisect-skip): Skip the current candidate (or REV): it cannot be tested
* [`vl bisect run`](#vl-bisect-run): Bisect automatically: run CMD on each candidate in a throwaway sandbox (exit 0 good, 125 skip, 1-127 bad, anything else aborts). The working copy is never touched, and nothing is recorded
* [`vl bisect reset`](#vl-bisect-reset): End the bisection and return to where it started
* [`vl bisect log`](#vl-bisect-log): Show the bisection's steps so far

## `vl bisect start`

Start a bisection between a bad and one or more good snapshots

```text
vl bisect start [OPTIONS] --bad <REV> --good <REV>
```

Options:

| | |
|---|---|
| `--bad <REV>` | A snapshot that has the problem (required) |
| `--good <REV>` | A snapshot that does not have the problem (repeatable) (required) |

## `vl bisect good`

Mark the current candidate (or REV) good

```text
vl bisect good [OPTIONS] [REV]
```

Arguments:

| | |
|---|---|
| `<REV>` | Snapshot to mark (default: the current candidate) |

Options:

| | |
|---|---|
| `--discard` | Move on even if the candidate's change holds edits (they stay in that change) |

## `vl bisect bad`

Mark the current candidate (or REV) bad

```text
vl bisect bad [OPTIONS] [REV]
```

Arguments:

| | |
|---|---|
| `<REV>` | Snapshot to mark (default: the current candidate) |

Options:

| | |
|---|---|
| `--discard` | Move on even if the candidate's change holds edits (they stay in that change) |

## `vl bisect skip`

Skip the current candidate (or REV): it cannot be tested

```text
vl bisect skip [OPTIONS] [REV]
```

Arguments:

| | |
|---|---|
| `<REV>` | Snapshot to skip (default: the current candidate) |

Options:

| | |
|---|---|
| `--discard` | Move on even if the candidate's change holds edits (they stay in that change) |

## `vl bisect run`

Bisect automatically: run CMD on each candidate in a throwaway sandbox (exit 0 good, 125 skip, 1-127 bad, anything else aborts). The working copy is never touched, and nothing is recorded

```text
vl bisect run [OPTIONS] -- <COMMAND>...
```

Arguments:

| | |
|---|---|
| `<COMMAND>…` | Command and arguments (put them after `--`) (required; after `--`) |

Options:

| | |
|---|---|
| `--with-isolated` | Copy local-only (isolated) files such as .env into each sandbox |
| `--trust-partial` | Trust verdicts on candidates you cannot fully read (by default they are skipped) |

## `vl bisect reset`

End the bisection and return to where it started

```text
vl bisect reset [OPTIONS]
```

## `vl bisect log`

Show the bisection's steps so far

```text
vl bisect log [OPTIONS]
```

---

[All commands](README.md) · [User guide](../guide/README.md)
