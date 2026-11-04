<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl submodule`

Git submodules: pinned commits of other Git repositories, fetched with `git` only when you run `vl submodule update`

Subcommands:

* [`vl submodule status`](#vl-submodule-status): Show each submodule's pinned commit and the commit checked out in it
* [`vl submodule update`](#vl-submodule-update): Clone or fetch submodules with `git` (URLs from `.gitmodules`) and check out their pinned commits
* [`vl submodule set`](#vl-submodule-set): Pin the submodule at PATH to COMMIT
* [`vl submodule add`](#vl-submodule-add): Record a Git repository as a submodule at PATH (cloning URL there if PATH does not exist yet)

## `vl submodule status`

Show each submodule's pinned commit and the commit checked out in it

```text
vl submodule status [OPTIONS] [PATHS]...
```

Arguments:

| | |
|---|---|
| `<PATHS>…` | Only these submodules (default: all) |

## `vl submodule update`

Clone or fetch submodules with `git` (URLs from `.gitmodules`) and check out their pinned commits

```text
vl submodule update [OPTIONS] [PATHS]...
```

Arguments:

| | |
|---|---|
| `<PATHS>…` | Only these submodules (default: all) |

Options:

| | |
|---|---|
| `--allow-local` | Allow `.gitmodules` URLs that are local paths or `file://` |

## `vl submodule set`

Pin the submodule at PATH to COMMIT

```text
vl submodule set [OPTIONS] <PATH> <COMMIT>
```

Arguments:

| | |
|---|---|
| `<PATH>` | Path of the submodule (required) |
| `<COMMIT>` | Full Git commit id to pin (required) |

## `vl submodule add`

Record a Git repository as a submodule at PATH (cloning URL there if PATH does not exist yet)

```text
vl submodule add [OPTIONS] <URL> [PATH]
```

Arguments:

| | |
|---|---|
| `<URL>` | URL of the submodule's repository (written to `.gitmodules`) (required) |
| `<PATH>` | Where the submodule lives (default: the URL's last component) |

Options:

| | |
|---|---|
| `--name <NAME>` | The submodule's name in `.gitmodules` (default: its path) |
| `--allow-local` | Allow a URL that is a local path or `file://` |

---

[All commands](README.md) · [User guide](../guide/README.md)
