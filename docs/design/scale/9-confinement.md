# 9. Confinement for `vl ws exec` (Linux)

Status: **built** (2026-11-06), with the resource limits of `8-sandbox-limits.md`. Required for phase 1 (`docs/OVERVIEW.md`, "Required for phase 1: isolated agent sandboxes"). **No repository format change.** Configuration is device-local; nothing tracked can set it.

**What this is:** every `vl ws exec` on Linux runs its command inside a confined view of the machine, built by **bubblewrap** (`bwrap`, the tool Flatpak uses). The command sees the project at its real path, but it is the workspace's sandbox; it sees the computer's tools read-only; it does not see `~/.ssh`, `~/.gnupg`, the Veil identity, other projects or the user's other processes. CPU, memory, process and time limits apply.

**What it is not:** a defence against kernel exploits, nor a limit on what the command does with what it *is* given (the sandbox, injected secrets, the allow-list, the environment, the network). An agent given a secret can send it anywhere while the network is on.

## How a run is confined

`vl` builds a `bwrap` command line (`crates/vl/src/confine.rs`) and runs the user's command through it:

```text
[systemd-run --user --scope --quiet --collect -p MemoryMax=… -p MemorySwapMax=0 -p CPUQuota=… -p TasksMax=… --]
bwrap --die-with-parent --new-session --unshare-user --disable-userns --unshare-pid
      --unshare-ipc --unshare-uts --unshare-cgroup-try [--unshare-net]
      --ro-bind /usr /usr  (and /bin /sbin /lib* as symlinks or binds, /etc, /opt, /nix, /sys when present)
      --proc /proc --dev /dev --tmpfs /tmp --tmpfs /var/tmp --dir /run
      [--ro-bind <dir of /etc/resolv.conf's target> …]   (DNS, when it points into /run)
      --tmpfs $HOME
      --ro-bind <allowed> <allowed> …                    (the allow-list, read-only)
      --ro-bind /dev/null ~/.cargo/credentials.toml …    (known credential files inside allowed folders)
      --tmpfs $VEIL_HOME                                 (the Veil identity, always hidden)
      --bind <sandbox files> <project root>              (read-write, at the project's real path)
      --chdir <project root>/<the sub-folder vl was run from>
      --setenv HOME $HOME --setenv TMPDIR /tmp --setenv PWD …
      -- CMD…
```

- **Same project path.** The sandbox (`.veil/local/sandboxes/NAME/files`, or the `--ephemeral` directory) is bound read-write at the project's canonical path, and the command starts in the same sub-folder the user ran `vl` from (the root if the sandbox has no such folder, e.g. with `--only`). The real project, its `.veil` (the store, other workspaces' sandboxes) included, is not visible: the bind replaces it.
- **The computer's tools, read-only and live:** nothing is copied, so start-up costs milliseconds.
- **Private by default:** an empty, writable `HOME` and `/tmp` (tmpfs, gone after the run), a fresh `/proc` showing only the sandbox's processes, no other mount of the real `/home`, `/run`, `/var` or `/media`.
- **The allow-list** adds folders or files of the machine, always read-only: toolchains and the agent tool's own configuration. Defaults (those that exist): `~/.cargo`, `~/.rustup`, `~/.local/bin`, `~/.local/share/claude`, `~/.nvm`, `~/.pyenv`, `~/.volta`, `~/.bun`, `~/.deno`, `~/.claude`, `~/.claude.json`, `~/.codex`, `~/.gemini`. **Never `~/.ssh`, `~/.gnupg` or the Veil home.** More come from `--allow PATH` and from `[exec.confine] allow = [...]` in `.veil/local/config.toml` and `$VEIL_HOME/config.toml` (device-local only). `~/.cargo/credentials` and `credentials.toml` are masked even when `~/.cargo` is allowed, and `$VEIL_HOME` is masked even when an allowed folder contains it.
- **Network on by default** (agents call their model's API); `--no-network` adds `--unshare-net` (only a private loopback).
- **Signals.** `--new-session` detaches the command from the terminal (no `TIOCSTI` injection), so the terminal's Ctrl-C reaches `vl` only. `bwrap` runs in its own process group; `vl` forwards SIGINT and SIGQUIT to the command's process group (as the terminal would) and SIGTERM and SIGHUP to the command (BUG-550), through a pidfd, so a reused pid is never signalled.
- **When the command exits, everything it started stops** (the pid namespace ends). Unconfined runs keep the old behaviour (background processes keep running).
- **When `vl` dies** (`kill -9`), `--die-with-parent` kills the sandbox's processes; the reaper then cleans up as before.

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

1. **Reading private files** (`~/.ssh`, `~/.gnupg`, cloud credentials, other projects, the Veil identity, the real `.veil` store with cloaked plaintext, other workspaces' sandboxes).
   - *Invariant:* the root is an empty tmpfs; only the paths above are mounted; `HOME` is an empty tmpfs; `$VEIL_HOME` is masked last; the project path is the sandbox.
   - *Tests:* `HOME/.ssh/id_test` planted in a fake home is not visible; `$VEIL_HOME/identity.json` is not visible (also when an allowed folder contains it); the real project's `.veil` is not visible; `~/.cargo/credentials.toml` is masked.
2. **Writing outside the sandbox** through `..`, absolute paths, symlinks (absolute, relative, `/proc/self/root`, `/proc/1/root`, `/proc/self/cwd`).
   - *Invariant:* the only writable mounts are the sandbox and tmpfs; system paths and the allow-list are read-only; `/proc` belongs to the sandbox's pid namespace, so `/proc/*/root` is the sandbox's own root.
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
    - *Invariant:* `--die-with-parent`; the scope is collected when empty; the reaper and the sweep work as before.
    - *Test:* `kill -9` of `vl` mid-run: the command's processes are gone, the injected file is removed, no `veil-exec-*` scope remains.
11. **`bwrap` missing or unusable.**
    - *Invariant:* the probe fails before anything is touched; nothing runs unconfined without `--unconfined`.
    - *Tests:* `PATH` without `bwrap`, and a `bwrap` that fails: the run fails with the install hint, and the manifest is unchanged.
12. **Hostile input:** allow paths (relative, missing, `/`, odd characters, starting with `-`), `HOME` (unset, relative, `/`), oversized or malformed configuration, sizes and durations that overflow, signals before the command starts, concurrency.
    - *Invariant:* allow paths must be absolute and exist (missing defaults are skipped; a missing explicit one is an error); `/` is refused; values are passed as separate arguments (no shell); configuration over 1 MiB, or malformed, is an error, never silently dropped.
    - *Tests:* each of these.
13. **The allow-list as a write channel.**
    - *Invariant:* always `--ro-bind`.
    - *Test:* writing into an allowed folder fails, and its hash is unchanged.
14. **What confinement does not cover** (documented in the guide):
    - the environment is passed through (agents need their API keys);
    - the network, when on;
    - kernel vulnerabilities (no seccomp filter yet);
    - the limits are soft in the fallback.

## Left for later

- **macOS**: Apple's sandbox profiles (`sandbox-exec`), weaker, documented as such.
- **`--container IMAGE`** (Docker or Podman), with the sandbox at the same path.
- `vl bisect run` still runs unconfined.
- A seccomp filter (Flatpak's list).
