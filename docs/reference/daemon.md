<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl daemon`

The Veil daemon: one object cache shared by every thin clone on this machine (it runs by default; `vl daemon stop` turns it off)

Subcommands:

* [`vl daemon status`](#vl-daemon-status): Show the daemon: its object store, what it served and the servers it reads from
* [`vl daemon start`](#vl-daemon-start): Start the daemon, and let `vl` start it again whenever a thin clone needs it (the default)
* [`vl daemon stop`](#vl-daemon-stop): Stop the daemon and keep it off: `vl` reads from the server directly until `vl daemon start`

## `vl daemon status`

Show the daemon: its object store, what it served and the servers it reads from

```text
vl daemon status [OPTIONS]
```

## `vl daemon start`

Start the daemon, and let `vl` start it again whenever a thin clone needs it (the default)

```text
vl daemon start [OPTIONS]
```

Options:

| | |
|---|---|
| `--cache-size <CACHE_SIZE>` | Bound of the daemon's object store (bytes, or with K, M or G); default 20G or a tenth of the disk, whichever is less |

## `vl daemon stop`

Stop the daemon and keep it off: `vl` reads from the server directly until `vl daemon start`

```text
vl daemon stop [OPTIONS]
```

---

[All commands](README.md) · [User guide](../guide/README.md)
