# 9. Confinement for `vl ws exec` (Linux)

Status: **built** (2026-11-06), with the resource limits of `8-sandbox-limits.md`; the allow-list writable through per-workspace layers since 2026-11-07 (BUG-1025). Required for phase 1 (`docs/OVERVIEW.md`, "Required for phase 1: isolated agent sandboxes"). **No repository format change.** Configuration is device-local; nothing tracked can set it.

**What this is:** every `vl ws exec` on Linux runs its command inside a confined view of the machine, built by **bubblewrap** (`bwrap`, the tool Flatpak uses). The command sees the project at its real path, but it is the workspace's sandbox; it sees the computer's tools read-only, and its toolchains and agent configuration through a layer of its own; it does not see `~/.ssh`, `~/.gnupg`, the Veil identity, other projects or the user's other processes. CPU, memory, process and time limits apply.

**What it is not:** a defence against kernel exploits, nor a limit on what the command does with what it *is* given (the sandbox, injected secrets, the allow-list, the environment, the network). An agent given a secret can send it anywhere while the network is on.

## How a run is confined

`vl` builds a `bwrap` command line (`crates/vl/src/confine.rs`) and runs the user's command through it:

```text
[systemd-run --user --scope --quiet --unit veil-exec-… [--expand-environment=no] -p MemoryMax=… -p MemorySwapMax=0 -p CPUQuota=… -p TasksMax=… --]
bwrap --die-with-parent --new-session --unshare-user --disable-userns --unshare-pid
      --unshare-ipc --unshare-uts --unshare-cgroup-try [--unshare-net]
      --ro-bind /usr /usr  (and /bin /sbin /lib* as symlinks or binds, /etc, /opt, /nix, /sys when present)
      --proc /proc --dev /dev --tmpfs /tmp --tmpfs /var/tmp --dir /run
      [--ro-bind <dir of /etc/resolv.conf's target> …]   (DNS, when it points into /run)
      --tmpfs $HOME
      --overlay-src <allowed> --overlay <layer>/upper <layer>/work <allowed> …
                                                         (an allowed folder: the real one below, the workspace's layer on top)
      --bind <layer copy> <allowed file> …               (an allowed file: the workspace's own copy)
      [--ro-bind <allowed> <allowed> …]                  (an allowed path that gets no layer; everything without overlayfs)
      --ro-bind /dev/null ~/.cargo/credentials.toml …    (known credential files inside allowed folders)
      --tmpfs $VEIL_HOME                                 (the Veil identity, always hidden)
      --tmpfs <every other name an allowed link gives the Veil home or the project>
      --bind <sandbox files> <project root>              (read-write, at the project's real path)
      --chdir <project root>/<the sub-folder vl was run from>
      --setenv HOME $HOME --setenv TMPDIR /tmp --setenv PWD …
      -- CMD…
```

- **Same project path.** The sandbox (`.veil/local/sandboxes/NAME/files`, or the `--ephemeral` directory) is bound read-write at the project's canonical path, and the command starts in the same sub-folder the user ran `vl` from (the root if the sandbox has no such folder, e.g. with `--only`). The real project, its `.veil` (the store, other workspaces' sandboxes) included, is not visible: the bind replaces it.
- **The computer's tools, read-only and live:** nothing is copied, so start-up costs milliseconds.
- **Private by default:** an empty, writable `HOME` and `/tmp` (tmpfs, gone after the run), a fresh `/proc` showing only the sandbox's processes, no other mount of the real `/home`, `/run`, `/var` or `/media`.
- **The allow-list** adds folders or files of the machine: toolchains and the agent tool's own configuration. **The real folders and files are never written:** what the command writes to them goes to the workspace's own layer (next section). Defaults (those that exist): `~/.cargo`, `~/.rustup`, `~/.local/bin`, `~/.local/share/claude`, `~/.nvm`, `~/.pyenv`, `~/.volta`, `~/.bun`, `~/.deno`, `~/.claude`, `~/.claude.json`, `~/.codex`, `~/.gemini`. **Never `~/.ssh`, `~/.gnupg` or the Veil home.** More come from `--allow PATH` and from `[exec.confine] allow = [...]` in `.veil/local/config.toml` and `$VEIL_HOME/config.toml` (device-local only). Cargo's `credentials` and `credentials.toml` (in `~/.cargo` and `$CARGO_HOME`) are masked even when an allowed folder holds them, and `$VEIL_HOME` and the real project are hidden even when an allowed folder contains them: under their own names and under every other name an allowed link gives them (an allowed `~/src` that links to the disk holding the project; BUG-848). An allowed path inside the Veil home or the project is refused. Without a usable `HOME` there are no defaults (BUG-854). Sockets and FIFOs in an allowed folder stay reachable (the guide says so).
- **Network on by default** (agents call their model's API); `--no-network` adds `--unshare-net` (only a private loopback).
- **Signals.** `--new-session` detaches the command from the terminal (no `TIOCSTI` injection), so the terminal's Ctrl-C reaches `vl` only. `bwrap` runs in its own process group; `vl` forwards SIGINT and SIGQUIT to the command's process group (as the terminal would) and SIGTERM and SIGHUP to the command (BUG-550), through a pidfd, so a reused pid is never signalled.
- **When the command exits, everything it started stops** (the pid namespace ends). Unconfined runs keep the old behaviour (background processes keep running).
- **When `vl` dies** (`kill -9`), the parent-death signal `vl` arms before it runs `systemd-run` or `bwrap` kills them, and `--die-with-parent` the sandbox's processes; the reaper then cleans up as before (BUG-851). `vl` killed in the moment between `bwrap` creating the sandbox's first process and that process arming its own parent-death signal leaves the command running, and `systemd-run` killed while systemd starts its scope can leave the empty scope active, or failed (a scope is not `--collect`ed: `vl` reads why it failed, then clears it). So what a dead `vl` left is stopped (BUG-852): every process still running a `bwrap` (or `systemd-run`) whose command line binds the sandbox, killed through a pidfd (killing the sandbox's init ends its pid namespace), and the `veil-exec-<pid>-*` scopes whose `vl` is gone (killed, stopped, `reset-failed`). The reaper does it as soon as `vl` dies; the next `vl ws exec` in the workspace (when its manifest shows an unfinished run), `vl ws rm`, and the sweep of throwaway sandboxes do it for a run with no reaper. Always under the sandbox's lock, or for a throwaway directory whose owner is gone: a live run is never touched.
- **`systemd-run` is never trusted to answer:** each call to it or to `systemctl` has a 5-second deadline (a user manager that does not answer means the polling fallback, and never delays recording; BUG-850), and the command reaches `bwrap` as given: with `--expand-environment=no` where `systemd-run` knows it (systemd 254 and later expand `$VAR` and `$$` otherwise; BUG-849).

### Writes to the allow-list: per-workspace layers (BUG-1025)

A read-only allow-list broke the tools it is for: `cargo build` after an agent adds a crate (downloads go to `~/.cargo/registry`), Claude Code, Codex and Gemini (settings and sessions in `~/.claude`, `~/.claude.json`), npm and pyenv installs. So writes go to a layer of the workspace's own, and the real folders stay as they are:

- **An allowed folder** is an overlay (`bwrap --overlay`): the real folder is the lower layer, read-only; the upper layer is `.veil/local/sandboxes/<ws>/layers-<id>/<name>-<hash>/upper` (with its `work` beside it), in the sandbox's private state (`0700`, applied again at every run: a `chmod` in a run does not last), never in its files: it is not recorded, synced or seen by another workspace. `<name>` is the folder's last component, readable; `<hash>` is 16 hex digits of BLAKE3 over the whole path. Writes, deletions (whiteouts) and renames stay in the upper layer and are there for the workspace's later runs; files the command did not change stay live. **`<id>`** is 16 hex digits of BLAKE3 over the workspace's identity, a random id the view records when the workspace is made (`WorkspaceState.id`; `layers` for a workspace made before it existed): a workspace that `vl undo` removed, made again under its name, is another workspace, with other layers; the first one finds its own again after `vl redo` (BUG-1031). The sandbox's manifest records the same id, and a sandbox whose id is not the workspace's is set aside whole (`unrecorded-…`), never synced into, re-imported or recorded (BUG-1033).
- **An allowed file** (`~/.claude.json`) gets the workspace's own copy, `layers-<id>/<name>-<hash>` (`0600`, `0700` for an executable, applied again at every run), made from the real file on first use and bound read-write. A rename onto it fails (`EBUSY`); Claude Code then writes it in place. Only a **regular** file is copied, opened without blocking and checked once open; a socket, FIFO or device is bound as it is (read-only, still reachable), never opened or copied (BUG-1032).
- **Thrown away instead** in an `--ephemeral` run, and in a run with `--with-isolated`: `--tmp-overlay`, and copies in a throwaway directory under `$TMPDIR` (`veil-ws-home-<pid>-…`, removed after the run, by the reaper or by the sweep). A command given secrets keeps nothing it wrote outside its files: a copy of a secret, or an agent's transcript that quotes one, does not outlive the run.
- **No layer** (read-only, as before, and the `running …` line says `read-only: PATH`) for a folder that holds the project (its `.veil` holds the layers, and overlayfs refuses an upper layer inside its lower one), or anything hidden below its top level (the Veil home under an allowed link; a `$CARGO_HOME` deep inside an allowed folder). A hidden path directly inside a layer (cargo's credentials) is a mount point: it cannot be deleted, renamed or replaced.
- **Masks still win.** Cargo's credentials, the Veil home and the real project are mounted over the layers, last. Whatever an earlier run left in a layer at a masked path (a folder, a link, a FIFO, a file, made before the real file existed) is removed from the upper layer first (links removed, never followed), so the mask always lies on the real entry and always mounts (BUG-1030).
- **Each run checks the layers** with a run of `true` (after the workspace's lock, before the command). If overlayfs does not work (a kernel before 5.11, a restricted user namespace, a filesystem that cannot hold an upper layer), the run goes on with the allow-list read-only and `vl` says so, naming the cause it found (overlayfs itself, tried on `/usr`, or the workspace's own layers, which deleting their folder starts over): `the allow-list is read-only in this run (overlayfs does not work here: …), or (the workspace's layers could not be mounted: …); cargo cannot download crates, and coding agents cannot save their settings or sessions`. `vl doctor` reports which applies here. Every set-up step has a deadline of 30 s (each `bwrap` probe, each copy): a hung filesystem fails the step, never hangs `vl` while it holds the workspace's lock.
- **Lifecycle.** `vl ws rm` deletes the layers with the sandbox; a rebuild of the sandbox keeps them. To start over from the real folders, delete `.veil/local/sandboxes/<ws>/layers-*` (while nothing runs in the workspace). The copy of a file is not refreshed from the real one: the workspace keeps its own.
- **Disk** (measured 2026-11-07): `cargo add serde_json && cargo build` into an empty `~/.cargo` leaves a 4.6 MiB layer; `tokio --features full`, 26 MiB (15 MiB of it extracted sources); the same build over a `~/.cargo` that already holds the crates, 432 KiB (index cache entries and lock files cargo rewrites).

### Resource limits (`8-sandbox-limits.md`)

```text
vl ws exec NAME [--memory 4G] [--cpus 2] [--cpu-time 30m] [--pids 512] [--timeout 45m] [--limits best-effort|strict] -- CMD…
```

Defaults from `[exec.limits]` (`memory`, `cpus`, `cpu-time`, `pids`, `timeout`, `mode`) in the same two device-local files; flags win.

| | systemd user scope (when `systemd-run --user` works) | fallback: rlimits and polling |
|---|---|---|
| memory | `MemoryMax`, `MemorySwapMax=0`: hard (the kernel's OOM killer) | RSS of the sandbox's processes polled every 100 ms: soft |
| cpus | `CPUQuota`: hard | unavailable |
| cpu-time | `cpu.stat` polled: hard kill | `RLIMIT_CPU` per process plus the tree's total polled: soft for the tree |
| pids | `TasksMax`: hard (forks fail) | processes counted: soft (killed when over) |
| timeout | hard | hard |

- **A limit stops the whole sandbox:** SIGTERM to every process in it, then SIGKILL after 10 s (killing `bwrap`, whose pid namespace takes everything with it). Exceeding `MemoryMax` is the kernel's OOM kill; `vl` reads `memory.events` and `pids.events` to say which limit fired.
- **`vl` and the reaper are never inside the scope or the limits.** Recording, the scanner, removal of injected secrets and quarantine always run. The run is recorded as usual; `vl` prints `stopped: memory limit (64 MiB) reached`.
- **`--limits strict`** refuses before anything is touched when a requested limit would be soft or unavailable; **`best-effort`** (the default) runs and prints one line naming them.
- **No limits by default** (unchanged behaviour); the guide suggests an agent profile.
- Limits need confinement: they conflict with `--unconfined`.
- **Not built** from 8's sketch: the delegated-cgroup mechanism, `--pids-mode=rlimit`, `--memory-mode=address-space`, macOS limits, the doctor's sum of live scopes, and the "(stopped by …)" suffix in the operation description.

### Failing safe

- **Default on** on Linux. Before anything is touched (no sync, no injection, the manifest unchanged), `vl` runs the confinement once with `true` as the command. If `bwrap` is missing or unusable, the run fails: "install bubblewrap (`apt install bubblewrap`)", with `bwrap`'s own error, and `--unconfined` as the explicit, warned opt-out.
- **Off elsewhere** (macOS until its sandbox profiles are built): runs are unconfined as before; confinement and limit flags are refused there.
- `vl doctor` reports whether confinement and which limit mechanism work on this machine.

## Threat review

The attacker is **the command** (a coding agent, a test suite, a dependency's build script), running as the user. It controls everything it executes and writes. The goal: it can change only its sandbox, and read only the sandbox, the computer's public tools, the allow-list and what it is given (environment, injected secrets).

1. **Reading private files** (`~/.ssh`, `~/.gnupg`, cloud credentials, other projects, the Veil identity, the real `.veil` store, other workspaces' sandboxes).
   - *Invariant:* the root is an empty tmpfs; only the paths above are mounted; `HOME` is an empty tmpfs; `$VEIL_HOME` is masked last; the project path is the sandbox.
   - *Tests:* `HOME/.ssh/id_test` planted in a fake home is not visible; `$VEIL_HOME/identity.json` is not visible (also when an allowed folder contains it); the real project's `.veil` is not visible; `~/.cargo/credentials.toml` is masked.
2. **Writing outside the sandbox** through `..`, absolute paths, symlinks (absolute, relative, `/proc/self/root`, `/proc/1/root`, `/proc/self/cwd`).
   - *Invariant:* the only writable mounts are the sandbox, tmpfs and the workspace's layers; system paths are read-only; **writes to the allow-list go to a per-workspace layer, and the real folders and files are never modified** (item 14); `/proc` belongs to the sandbox's pid namespace, so `/proc/*/root` is the sandbox's own root.
   - *Test:* a command tries every one of these against a canary directory, the real project and the fake home; a before/after hash of each is unchanged, and the writes into the sandbox land in the sandbox.
3. **Seeing or signalling the user's other processes; other workspaces.**
   - *Invariant:* `--unshare-pid` with a fresh `/proc`; each run binds only its own sandbox.
   - *Tests:* a marker process outside is absent from the sandbox's `/proc`; two concurrent workspaces cannot see each other's files.
4. **The network** with `--no-network`.
   - *Invariant:* `--unshare-net` leaves only a private loopback.
   - *Test:* connecting to a listener on the host's `127.0.0.1` fails with `--no-network` and succeeds without it.
5. **Agent sockets and IPC** (ssh-agent, gpg-agent, the D-Bus session bus, Docker's socket).
   - *Invariant:* path sockets live in `/run/user`, `/run` or `$HOME`, none of which is mounted; `--unshare-ipc` hides SysV IPC. **Abstract** Unix sockets (X11's, some D-Bus setups) follow the network namespace: reachable with the network on, gone with `--no-network`. Documented.
   - *Test:* a socket under the fake home named by `SSH_AUTH_SOCK` is not reachable.
6. **Terminal injection** (`TIOCSTI`).
   - *Invariant:* `--new-session`; `vl` forwards Ctrl-C and Ctrl-\ itself.
   - *Test:* the existing Ctrl-C test passes confined (exit 130, recorded).
7. **Escaping the namespaces** (nested user namespaces, setuid binaries).
   - *Invariant:* `--disable-userns`; `bwrap` sets `no_new_privs` and drops all capabilities.
   - *Test:* `unshare -U true` fails inside; `NoNewPrivs: 1`.
8. **Configuration from repository content** (a teammate's tracked file widens the allow-list or drops limits).
   - *Invariant:* read only from flags, `.veil/local/config.toml` and `$VEIL_HOME/config.toml`; the command cannot reach either (both hidden).
   - *Test:* a tracked `config.toml` with `[exec.confine] allow` has no effect.
9. **Killing the recorder** (the command exhausts memory or pids, or is killed by a limit).
   - *Invariant:* `vl` and the reaper are outside the scope and the limits.
   - *Tests:* a memory hog, a CPU loop and a process storm are each stopped, and `vl` records afterwards; with `--with-isolated` the injected file is removed after the memory kill.
10. **Leftovers after `vl` is killed.**
    - *Invariant:* `vl`'s parent-death signal and `--die-with-parent`; for the moment neither covers, the reaper, the next run and the sweep stop what a dead run left (its processes and its scope, BUG-852).
    - *Tests:* `kill -9` of `vl` at 16 moments of a run, 4 times: the command's processes are gone, the injected file is removed, no `veil-exec-*` scope remains; a stand-in for an init that outlived `vl` is stopped by the next run and by `vl ws rm`.
11. **`bwrap` missing or unusable.**
    - *Invariant:* the probe fails before anything is touched; nothing runs unconfined without `--unconfined`.
    - *Tests:* `PATH` without `bwrap`, and a `bwrap` that fails: the run fails with the install hint, and the manifest is unchanged.
12. **Hostile input:** allow paths (relative, missing, `/`, odd characters, starting with `-`), `HOME` (unset, relative, `/`), oversized or malformed configuration, sizes and durations that overflow, signals before the command starts, concurrency.
    - *Invariant:* allow paths must be absolute and exist (missing defaults are skipped; a missing explicit one is an error); `/` is refused; values are passed as separate arguments (no shell); configuration over 1 MiB, or malformed, is an error, never silently dropped.
    - *Tests:* each of these.
13. **The allow-list as a write channel.**
    - *Invariant:* the real folder is the lower layer of an overlay, a real file is copied: neither is ever written (item 14). A socket or FIFO in an allowed folder can still be connected to or written (documented in the guide; the default folders hold none).
    - *Tests:* every kind of change to allowed folders and files (append, truncate, `chmod`, rename, `rm -rf`, links, `touch -d`), in a kept, a throwaway and an injected run, leaves them byte for byte and mtime as they were; renames and hard links across the boundary too.
14. **The layers** (BUG-1025).
    - *Hooks and configuration the command plants in its layers* (`~/.claude/settings.json` hooks, a `~/.cargo/config.toml` runner): they persist into **later runs of the same workspace only**, which are confined just the same; the real folders, other workspaces and your own unconfined tools never read them. The command can already plant the same in its sandbox's files (a project `.cargo/config.toml`, `.claude/settings.json`), which are recorded and reach the project when merged; a layer is never recorded. Deleting `layers/` resets them.
    - *Links in an upper layer pointing outside:* they resolve inside the confinement, where the target is not mounted; `vl` never follows them (`vl ws rm` removes the tree without following links; a link where a file copy belongs is removed and the copy made afresh, created exclusively).
    - *The upper layer's place and permissions:* in the sandbox's private state (`0700` directories, `0600` copies (`0700` executables), owned by the user, checked like the sandbox's own), inside the real project's `.veil`, which the command never sees; only through the overlay can it change what is there, and overlayfs refuses or escapes its own `user.overlay.*` attributes set through the overlay (Linux 7.0 escapes them: they land in the upper layer under another name and mean nothing to overlayfs); `bwrap` mounts with `userxattr`, so `redirect_dir=nofollow`: renaming a real folder copies it, through the masks. A `chmod` in a run can leave the upper folder or a copy at another mode until the next run's set-up applies `0700` and `0600` again; the folders above them stay `0700` throughout.
    - *Masks:* mounted after the layers; a hidden path directly in a layer is a mount point (deleting or renaming it fails with `EBUSY`, a hard link with `EXDEV`), and a folder with anything hidden deeper gets no layer, so no rename of a folder above a hidden path can move it out from under its mask. What a run leaves at a masked path before the real file exists is removed at the next set-up (BUG-1030).
    - *Other workspaces and other users:* each run mounts only its own workspace's layers (keyed by the workspace's identity, not its name: BUG-1031), under the workspace's lock (overlayfs must never mount one upper layer twice); a throwaway run's are its own; other users cannot enter the sandbox directory.
    - *Secrets:* a run with `--with-isolated` (and every `--ephemeral` run) gets throwaway layers, so no injected secret, nor anything derived from one, stays in a layer; cargo's credentials and the Veil identity are never copied into one.
    - *No overlayfs:* the run goes on read-only and says what that breaks; never silently.
    - *Tests:* `bug_1025_*` (cargo, the real `cargo install` included; agents' settings and sessions; persistence per workspace), `the_real_allowed_folders_and_files_are_unchanged_after_runs_that_write_them`, `masks_hold_through_the_layers_in_this_run_and_the_next` (credentials, a Veil home directly in a layer and one deeper, a folder holding the project; nothing secret in any layer), `links_planted_in_the_layers_lead_nowhere_outside`, `layers_are_private_and_go_with_the_workspace`, `throwaway_and_injected_runs_keep_no_writes`, `without_overlayfs_the_allow_list_is_read_only_and_vl_says_so` (also a broken layer, named as the cause), `bug_1030_*` (folders, links, files and FIFOs left at masked paths), `bug_1031_*` and `bug_1033_*` (a new workspace under an old name), `bug_1032_*` (an allowed socket and FIFO), `unusual_changes_to_the_allow_list_leave_the_real_folders_as_they_were` (renames across layers, hard links, delete and recreate, file to folder or link, extended attributes, `user.overlay.*`), `concurrent_workspaces_keep_their_own_layers`, and the BUG-852 leftover tests with layers present.
15. **What confinement does not cover** (documented in the guide):
    - the environment is passed through (agents need their API keys);
    - the network, when on;
    - kernel vulnerabilities (no seccomp filter yet);
    - the limits are soft in the fallback.

## Left for later

- **macOS**: Apple's sandbox profiles (`sandbox-exec`), weaker, documented as such.
- **`--container IMAGE`** (Docker or Podman), with the sandbox at the same path.
- `vl bisect run` still runs unconfined.
- A seccomp filter (Flatpak's list).
