# 8. Resource limits for `vl ws exec`

Status: design and threat review, **not built** (Scion 4.7). A client-side item, independent of the server. ("Scope" here means a systemd scope.) **No repository format change.** Limits are device-local configuration and command-line flags.

**What this is:** a guard against runaway agents and builds (memory leaks, fork loops, hung test suites) on a shared developer machine. **What it is not:** a security boundary. The command runs as the same user, and a deliberately hostile one can leave any user-level limit (threat 1). That stays documented in the guide.

## Today

`crates/vl/src/sandbox.rs` `run_command` spawns the command with `Command::spawn` in `vl`'s own process group, and `Interrupts` forwards SIGTERM and SIGHUP to it. A reaper (`spawn_reaper`, its own process group) takes injected files out again if `vl` dies. Background processes the command leaves running are **not killed**, because a dev server is often the point.

## Design sketch

### CLI and configuration

```text
vl ws exec NAME [--memory 4G] [--cpus 2] [--cpu-time 30m] [--pids 512] [--timeout 45m]
                [--limits best-effort|strict] -- CMD…
```

- **Defaults** come from `[exec.limits]` in `.veil/local/config.toml`, then `$VEIL_HOME/config.toml`. Both are device-local; nothing tracked can set limits (threat 10).
- **`--limits strict`** fails before running when a limit cannot be enforced on this machine. **`best-effort`** (the default) runs, and prints one line naming any limit that is soft or unavailable.
- **`vl doctor`** reports which mechanism this machine has.

### Mechanisms, in order (`crates/vl/src/limits.rs`)

| mechanism | when | memory | cpus (rate) | cpu-time (total) | pids | timeout |
|---|---|---|---|---|---|---|
| **systemd user scope** | Linux, `systemd-run --user` reaches the user manager | `MemoryMax` (+ `MemorySwapMax=0`), hard | `CPUQuota`, hard | `cpu.stat` polled, hard kill | `TasksMax`, hard | `systemctl --user kill` / `cgroup.kill`, hard |
| **delegated cgroup v2** | `vl`'s cgroup tree is writable (rootless containers, `Delegate=yes`) | `memory.max`, hard | `cpu.max`, hard | `cpu.stat` polled | `pids.max`, hard | `cgroup.kill` (5.14+), else signal every pid in `cgroup.procs` until empty |
| **rlimits + polling** | any Unix | RSS of the descendants polled every 250 ms, soft | — | `RLIMIT_CPU` per process + polling, soft for the tree | descendants counted, soft | process group SIGTERM → 10 s → SIGKILL |

- **The systemd path** runs `systemd-run --user --scope --quiet --collect -p … -- CMD…`. With `--scope`, `systemd-run` registers the scope and then **execs the command in place**, so the pid `vl` waits on and forwards signals to is the command's (BUG-550's forwarding is unchanged).
- **The cgroup path** creates `<delegated root>/veil-<ws>-<rand>` and sets its files. The child moves itself into it (`write "0" to cgroup.procs`) in `pre_exec`, between fork and exec (`open`/`write` are async-signal-safe). `clone3(CLONE_INTO_CGROUP)` is used where available.
- **`vl` and the reaper are never placed in the limited cgroup or scope,** so recording, cleanup of injected files (`remove_injected`) and the scrub always run, whatever happens to the command.
- **On macOS** there are no cgroups:
  - `RLIMIT_CPU` per process;
  - memory polled through `proc_pid_rusage` (`ri_phys_footprint`) over `proc_listchildpids` descendants;
  - pids counted the same way;
  - the timeout through the process group.
  - All soft except the timeout and per-process CPU time. **`RLIMIT_AS` and `RLIMIT_DATA` are not enforced by macOS** and are never used.
- **Not used by default:**
  - `RLIMIT_NPROC` counts **all** of the user's processes, so a sandbox limit would break, or be broken by, the rest of the session;
  - `RLIMIT_AS` breaks runtimes that reserve address space (Go, Node, JVM, ASan).
  - Both are available as `--pids-mode=rlimit` and `--memory-mode=address-space` for those who want them.
- **Signalling in the fallback** uses pidfds (`pidfd_open`, `pidfd_send_signal`) on Linux 5.3+, and on macOS checks each pid's start time (`lock.rs` `process_start`) before signalling. So a reused pid is never signalled.

### Timeouts and background processes

- **Without `--timeout`**, as today: the command's background processes keep running after `ws exec` returns, still inside the scope or cgroup, so memory and pid limits keep applying to them. The scope is collected when it empties.
- **With `--timeout`**, at the deadline **everything in the sandbox's scope or cgroup is stopped**, background processes included: SIGTERM, then 10 s, then SIGKILL or `cgroup.kill`. In the fallback, the process group is stopped, and descendants that changed group are reported as possibly left running.

### Results

- **The exit code** is `128 + signal`, as today.
- **`vl` says which limit fired**, from `memory.events` `oom_kill`, the timeout or the CPU-time counter: "killed: memory limit (4 GiB) reached".
- **The run is recorded as usual** (steps 7–9 do not depend on the exit status). The operation description gains "(stopped by memory limit)", so the output of a killed run is visible as such in `vl op log`.

## Threat review

1. **Escaping the limit.** A same-user command can call `systemd-run --user` itself, write its pid to a writable sibling cgroup, or `setsid` out of the process group.
   - *Invariant:* documented: limits stop runaway processes, not hostile ones. Nothing in Veil's confidentiality depends on them.
   - *Test:* a well-behaved fork loop (`:(){ :|:& };:` bounded by the test) is capped at `--pids`, and a 10 GiB allocation is killed at `--memory 1G`.
2. **Killing `vl` or the reaper.** If `vl` is OOM-killed with the command, injected secrets stay in the sandbox and the run is unrecorded.
   - *Invariant:* `vl` and the reaper stay in their original cgroup and process group.
   - *Test:* `ws exec --with-isolated --memory 256M -- memory-hog`. The command is killed, `vl` records, the injected files are gone, and the reaper exits cleanly.
3. **Timeouts and dev servers.**
   - *Invariant:* without `--timeout`, nothing the command started is killed by `vl`; with it, everything in the scope or cgroup is stopped at the deadline.
   - *Test:* both modes with a background `sleep 1000` child; check it is alive or gone.
4. **Killing an unrelated process** (pid reuse in the fallback).
   - *Invariant:* only pids proven to be descendants are signalled: by pidfd, or by start time on macOS.
   - *Test:* a `ProcessProbe`-style simulation in which a descendant exits and its pid is reused by a non-descendant before the kill sweep. It is not signalled.
5. **Per-user limits breaking the session** (`RLIMIT_NPROC`).
   - *Invariant:* never set unless asked for with `--pids-mode=rlimit`.
   - *Test:* `--pids 64` in fallback mode does not set `RLIMIT_NPROC` (read back through `/proc/<pid>/limits`).
6. **`RLIMIT_AS` breaking runtimes.**
   - *Invariant:* never set unless asked for.
   - *Test:* `node -e 1` (when available) runs under `--memory 1G` in every mode.
7. **A killed command's torn output** is recorded as its output.
   - *Invariant:* the recording applies every guard as for any run (scanner, quarantine, injected-secret guard, policy hold-back), so a torn file holding a secret is still caught; the operation is marked as stopped.
   - *Test:* kill a command half way through writing a file that holds an AWS key pattern. The file is quarantined, and the op description says "stopped by timeout".
8. **No mechanism available** (no user manager over SSH without lingering, a container without delegation).
   - *Invariant:* `best-effort` runs with soft limits and says so; `strict` refuses before anything is injected.
   - *Test:* `VEIL_EXEC_LIMITS_BACKEND=systemd|cgroup|poll|none` forces each path; `strict` with `none` exits non-zero before the sandbox is touched (manifest unchanged).
9. **Signal forwarding** (BUG-550).
   - *Invariant:* SIGTERM and SIGHUP to `vl` still reach the command (the in-place exec keeps its pid), and SIGINT and SIGQUIT are still ignored by `vl`.
   - *Test:* the existing signal tests, run under each backend.
10. **Limits defined by repository content.** A teammate's tracked file disables limits or sets absurd ones.
    - *Invariant:* limits are read only from flags and device-local configuration, never from the working copy (the same rule as hook and driver commands).
    - *Test:* a tracked `.veil-limits` or `config.toml` in the tree has no effect.
11. **Exhausting the host with many agents** (N agents × `--memory 4G` on 30 GB).
    - *Invariant:* documented, not prevented. `vl doctor` prints the sum of `MemoryMax` over live Veil scopes.
    - *Test:* the doctor output with two live scopes.
12. **Cgroup litter.** A crashed `vl` leaves an empty `veil-*` cgroup.
    - *Invariant:* empty `veil-*` cgroups older than 1 hour are removed by the next `ws exec` sweep (`sweep_stale`), never a non-empty one.
    - *Test:* create one, age it, sweep it.

## Open decisions

1. **`strict` or `best-effort` by default.**
   - *Recommendation:* `best-effort`, with the printed line. Agents' harnesses that need guarantees pass `--limits strict`.
2. **Default limits.**
   - *Recommendation:* none (unchanged behaviour). The guide gives a suggested agent profile (`--memory 4G --pids 1024 --timeout 60m`).
3. **Whether `--timeout` kills background processes.**
   - *Recommendation:* yes (above): a time limit that left a server running would not limit anything.
4. **`systemd-run` versus talking D-Bus directly.**
   - *Recommendation:* `systemd-run`: no D-Bus dependency in `vl`, and it is present wherever user scopes work.
