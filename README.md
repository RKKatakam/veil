<p align="left">
  <img src="assets/icon.svg" width="64" height="64" alt="Veil icon">
</p>

# Veil (`vl`)

**Version control built from scratch in Rust for the AI-agent era of coding — combining the [Jujutsu (`jj`)](https://martinvonz.github.io/jj/) change model with a Scion-style central Hub.**

> Pre-1.0 preview · Server-centric VCS · `jj` mental model (`@`, change IDs, op log, conflicts as data) · Not Git (no Git interop) · Linux & macOS

---

## Why Veil Exists — and Why It Matters for AI Coding Systems

Git was designed in 2005 for a handful of humans taking turns pushing commits from full local clones. That model breaks when software engineering shifts from engineers opening one PR at a time to **fleets of hundreds or thousands of autonomous AI agents and subagents** reading, branching, testing, and shipping continuously on the same codebase.

At agent speed, **version control becomes the core coordination bottleneck of AI engineering**:

- **Push races turn `main` into a retry storm.** When dozens or thousands of agents push at once, losers have to pull, rebase, and retry over and over — throttling merges to a crawl.
- **Full clones and worktrees don't scale.** Spinning up 50 agents shouldn't mean duplicating gigabytes of history and working trees on disk.
- **Conflicts and broken builds stall the entire fleet.** Traditional rebase conflicts leave conflict markers wedged in the tree, and one bad commit on `main` blocks every agent until a human bisects it.
- **All-or-nothing access is dangerous for autonomous agents.** Anyone who can clone a Git repo can read the whole repo — and local agents typically run unconfined with your `~/.ssh` keys and secrets in reach.

**Veil solves this at the architecture layer.** A central server (**Veil Hub**) stores the repository, enforces per-folder permissions on every read and query, batches concurrent landings onto `main` in a single atomic compare-and-swap (so agents never pull, rebase, or retry), isolates each agent in a millisecond workspace (and Linux sandbox), and automatically bisects and reverts broken landings so new agents always start from `main@tested`.

![Git for human teams vs Veil for AI agent fleets](assets/hero-architecture.svg)

**Where it came from.** Veil brings together three ideas:

- **Jujutsu (`jj`) on the client:** the working copy is always a change (`@`) with no staging area or index; every change has a stable reverse-hex change ID (`k–z`) separate from its BLAKE3 snapshot ID; conflicts are stored as structured data so rebases and merges always finish; descendants auto-rebase; every action is recorded in an undoable op log (`vl op log`, `vl undo` / `vl redo`); and named pointers (`vl tag`, like `jj bookmark`) replace Git's mutable active branch (`HEAD`).
- **Anthropic's [Scion](docs/design/scion-for-developers.md) on the server:** a central Hub, thin clients fetching on demand, lock-free uploads, server-batched landings onto `main`, and land-first / test-after (`main@tested`).
- **Theo's (t3.gg) thesis** in *"Git is holding us back"* that human-paced commits and branches bottleneck AI coding systems — turned into something any team can self-host from one laptop up to a distributed cluster. *(Veil is independent and not affiliated with or endorsed by Jujutsu, Anthropic, or t3.gg.)*

---

## The `jj` Model + `vl push` vs. `vl land`

If you know Jujutsu (`jj`), `vl` feels immediately familiar: `vl new`, `vl describe`, `vl edit`, `vl squash`, `vl split`, `vl abandon`, `vl duplicate`, `vl resolve`, `vl evolog`, `vl op log`, and `vl undo` all follow the `jj` workflow.

To keep thousands of concurrent agents from colliding on `main`, Veil separates **syncing a branch** from **shipping to `main`**:

- **`vl push`** sends your tags/branches and their snapshots to the Hub — ideal for an agent syncing work-in-progress on its own branch (just like `jj git push`, it moves a branch only if nobody else moved it). Pushing to a protected branch automatically routes through `vl land`.
- **`vl land`** hands a change (`fix-login@`) to the Hub's **landing service**, which merges and batches non-overlapping changes onto the newest `main` (or folds a subagent's branch into its parent with `vl land --onto <branch> --delete`) in a single atomic compare-and-swap — **no pull, no local rebase, no retry**.

---

## How Veil Fixes Git's Failure Modes for Agents

| What breaks with Git | What Veil (`vl`) does |
|---|---|
| Agents forget `git add` or get stuck in detached HEAD | **No staging, no index.** Every `vl` command auto-snapshots the working copy first; work cannot be lost by skipping a step. |
| A merge conflict halts a rebase with markers in files | **Merges and rebases always finish.** Conflicts are stored as structured data on the change for that agent — or another — to resolve cleanly. |
| 20 agents need 20 full clones or worktrees | **Millisecond workspaces.** `vl ws exec NAME --mount -- cmd` spawns an isolated view of any-sized repo in milliseconds; files fetch on demand. |
| Local agents run with full access to `~/.ssh` and host files | **Linux bubblewrap sandboxes** with private files, home, processes, ports, and CPU/RAM/time limits. *(Linux-only today; macOS runs unconfined. Copied secret values are refused on both.)* |
| Concurrent pushes to `main` race, fail, and retry | **Server-batched `vl land`.** The Hub lands changes onto the newest `main` in batches with zero client retries; only true conflicts return to their agent. |
| A broken `main` stalls the fleet until someone bisects | **Land first, test after.** Agents branch from `main@tested` (newest green `main`). The server auto-bisects failures and reverts the culprit. |
| Anyone who can clone can read the whole repo | **Server-enforced folder ACLs** on every response — files, logs, blame, search, diffs, PRs, and CI. Narrow an agent session to just the folders its task needs. |
| Failed approaches vanish and the next agent repeats them | **Recorded dead ends.** `vl attempt drop --reason "…"` keeps failed attempts and why they failed attached to the change. |
| Forged commit authors and `git reflog` archaeology | **Cryptographically signed attribution** (`--agent`, `--task`, `--run` under a human's signature) plus exact **`vl undo` / `vl redo`** for every command. |

An agent's entire lifecycle in four commands:

```sh
vl ws new fix-login                                           # starts from main@tested (newest green main)
vl ws exec fix-login --mount --private-ports --memory 4G \
   --agent "claude-code" --task "TASK-812" -- my-agent "fix login"   # sandboxed on Linux only
vl attempt drop fix-login@ --reason "lock ordering deadlocks" # preserve dead ends for the next agent
vl land fix-login@                                            # server lands on main: no pull, no retry
```

*(On macOS, omit `--private-ports` and `--memory`: bubblewrap sandboxing and resource limits are Linux-only for now, and `vl` refuses those flags on macOS where commands run unconfined.)*

Also built in: pull requests with risk-based approval rules, delayed-visibility **embargoes** for security fixes, automatic encryption for secret files (`.env`, keys), thin clones, a passkey-authenticated web UI, and server-side history, blame, and search in milliseconds.

---

## Measured at Agent Scale

Benchmarked across up to 12 machines on Google Cloud (`2026-11-20` & `21`, build `8efc94ab`, ~$39 total on Spot VMs) plus same-machine comparisons against Git on a 32-core NVMe host. Full raw tables, methodology, and every open miss live in **[docs/BENCHMARKS.md](docs/BENCHMARKS.md)** and [DEPLOY.md §12.11](docs/DEPLOY.md#1211-the-runs-on-google-cloud-2026-11-20-and-21).

### 1. Eliminating the `main` Bottleneck

![Veil landing throughput and daily capacity vs Anthropic Scion](assets/chart-landing-scale.svg)

- **Zero retry storms:** Batched server-side `vl land` sustained **207 landings/sec** (`206.7/s`) on one `main` across the GCP cluster (**185/s** protected; **182/s** with branch protection plus 3% overlapping and 2% conflicting changes) — compared to **6.6/s** for 50 racing pushes (27 collisions/op) and **20–30/s** for pull/rebase/retry loops. *(Note: the GCP saturation test deliberately offers 1,000/s — 5× cluster capacity — so excess requests are backpressured/timed out with p50 ~62 s.)*
- **Room for Scion-era merge volume:** Held over a day, even the realistic 20,000-agent YugabyteDB cluster sustains **450k `main` landings/day** (`5.2/s`) plus **1.4M subagent landings/day** (`16.0/s`) with **0 errors**, compared to Anthropic's reported **30,000+ merges/day** carried by Scion *(Scion's figure is daily production usage on a ~100 GB monorepo, not its ceiling)*.

### 2. Scaling Horizontally With YugabyteDB (3 → 6 Nodes)

![Horizontal scaling on Google Cloud: YugabyteDB 3 to 6 nodes and 20,000-agent fleet](assets/chart-horizontal-scaling.svg)

- **One hot repository scales across nodes:** Switching from colocated storage (**79%** load pinned to one node) to Veil's **hash layout** splits even a single busy repository across every node (**17%** max node share on 6 nodes), achieving **1.62×** own-branch `vl push` (`30.3 → 48.9/s`, passing the 1.6× gate with **0 errors**) and **1.70×** `main` landings (`4.0 → 6.8/s`; `1.63×` pushes in the merge workload).
- **20,000-agent realistic fleet (each agent forking 3 subagents):** Going from 3 to 6 small 8-vCPU nodes boosted every operation **2.2–2.7×** (`vl push` `70 → 162/s`, subagent `vl land` `5.9 → 16.0/s`, `main` `vl land` `2.4 → 5.2/s`), dropped push p50 from **4.0 s → 0.25 s**, achieved **0 errors** (vs. 118 on a single 56-vCPU PostgreSQL box), and landed **37% more branches/sec** onto `main`.

### 3. Client Speed vs. Git & Failover Integrity

![Veil vs Git client speed on 1 GB repository and operational gates](assets/chart-vs-git.svg)

- **Faster where agents feel it:** **3.1× faster** default clone of a 1 GB / 35k-file project (`9.4 s` thin default vs. Git's `29 s` full default), **2.6× faster** import (`4.2 s` vs. `10.9 s`), **5.4× faster** `status` with the background watcher running (`5.8 ms` vs. `31.5 ms`; `63–68 ms` with daemon stopped), and **< 300 ms** (`288 ms` cold / `259 ms` warm) to spawn a 200,000-file workspace — while `fsync`ing every commit for crash safety. *(Git remains faster on local `log -n 20`: `2.0 ms` vs. `8.1 ms`.)*
- **Exactly-once failover:** Killing the Hub node holding `main`'s landing lease mid-load passed every integrity check: **10,473 / 10,473 changes landed exactly once** (0 lost, 0 duplicated, 0 false confirmations), with lease takeover in **1.6 s** (`1,632 ms`). *(Miss: longest pause after stop was `2.46 s` against a `2.0 s` latency target.)*

> **Honest misses & open items** (tracked in [docs/BENCHMARKS.md](docs/BENCHMARKS.md) & [docs/BUGS.md](docs/BUGS.md)):
> - Multi-project `3 → 6` node scaling hit `1.07–1.58×` (missed `1.6×` target) because the fixed 300-agent benchmark only drove 6 nodes to ~50% CPU.
> - YugabyteDB costs **6–10× more DB CPU per push** than PostgreSQL and needs admission backpressure before saturation; PostgreSQL is better per core up to one big box, while YugabyteDB scales out and survives node/zone loss.
> - Single-repo branch pushes peaked at **393/s** (~5.5% of GitHub's 7,200/s internal benchmark) — bottlenecked on client round trips / MinIO writes, not CPU.
> - Unexplained anomalies still being investigated: PostgreSQL pulls lagged YugabyteDB at 10–100 agents, and 3-server landing dropped vs. 1–2 servers. Multi-region and `> 1 GB` cloud runs are not yet measured.

---

## Security, Permissions & Core Trade-offs

| Area | How Veil works |
|---|---|
| **Folder access** | Creator is admin; everything is **private by default**. Admins grant groups or people access to folders (`vl access billing/ finance`, `vl access src/ public`). Enforced by the server on every read, diff, log, search, PR, and CI call. |
| **Secrets** | `.env`, keys, `*.pem`, `*.tfstate`, etc. are **encrypted automatically** on the client and follow folder permissions. Personal private keys never leave the machine. Plain files are secret-scanned and quarantined on hits; `.veilpolicy` changes from others never silently weaken local protection. |
| **Embargoes** | Security fixes can merge to a hidden server line (`--embargo-for security --until +7d`) that does not exist in logs, pulls, search, or PRs for outsiders until release. |
| **Server-centric model** | Editing, `vl status`, commits, split/squash, `vl undo`/`redo`, and secret scanning work offline. Sharing (`push`, `pull`, `land`), cloning, unfetched thin-clone files, and whole-repo history/blame/search go through the Hub. |
| **Durability & storage** | Local commits `fsync` objects and operations (`F_FULLFSYNC` on macOS). Server metadata lives in PostgreSQL or YugabyteDB; file versions live in S3-compatible storage (**append-only in v1** — no background GC racing writers). |

Full trade-off analysis: [docs/BENCHMARKS.md#design-trade-offs](docs/BENCHMARKS.md#design-trade-offs) · Threat model: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) · Access model: [docs/VISIBILITY.md](docs/VISIBILITY.md).

---

## Install

Veil supports **Linux and macOS** (`x86_64` and `aarch64`; Windows is not supported). There are no prebuilt release binaries yet — build from source with Rust 1.80+ and a C compiler:

```sh
# Install the `vl` CLI
cargo install --locked --path crates/vl

# Optional: build the Veil Hub server (requires `make` + C compiler for jemalloc)
cargo build --release --locked -p veil-server
```

### Quick start

**Local workflow (no server needed to try):**

```sh
cd my-project
vl init                        # creates .veil/, default .veilpolicy, and your signing identity
vl status                      # no `git add` — working copy is already snapshotted
vl commit -m "first change"    # describe @ and open a fresh change on top
vl log                         # stable change ids (k–z) + BLAKE3 snapshot ids + ✓ signatures
```

**Run a local Veil Hub and land changes:**

```sh
# Terminal 1 — PostgreSQL + Veil Hub (generates a local self-signed cert in ~/veil-hub)
docker run -d --name veil-pg -e POSTGRES_USER=veil -e POSTGRES_PASSWORD=veil -e POSTGRES_DB=veil \
  -p 127.0.0.1:5432:5432 postgres:17-alpine
target/release/veil-server --database-url postgres://veil:veil@127.0.0.1:5432/veil \
  --data ~/veil-hub --listen 127.0.0.1:8443

# Terminal 2 — push & land without pulling or retrying
vl login veil://127.0.0.1:8443 --name alice --ca ~/veil-hub/self-signed-cert.pem
vl remote add origin veil://127.0.0.1:8443/acme
vl tag set main -r @- && vl push
echo "hello" >> notes.txt && vl commit -m "second change"
vl land                        # Hub atomically lands onto newest main
```

For full CLI grammar, `.veilpolicy` rules, completions, man pages, testing, embedding `veil-core` in Rust/WASM, and Linux/macOS filesystem notes (`vl doctor`, `VEIL_FS_FOLDING`, FUSE mounts), see **[docs/PLATFORM.md](docs/PLATFORM.md)**.

---

## Where It Stands

Veil is a **pre-1.0 preview**. Every planned feature is implemented and running across multi-machine cloud deployments; remaining work is performance tuning and closing the open items from the cloud runs.

| Component | Status |
|---|---|
| Client engine, BLAKE3 CAS, workspaces, Linux bubblewrap sandboxes | Built *(macOS sandbox not yet built)* |
| Veil Hub, folder ACLs, thin clones, S3 append-only storage, PG & YugabyteDB hash layout | Built & measured on 3 and 6 GCP nodes |
| Batched landing, `main@tested` auto-bisect/revert, PRs, embargoes, passkey web UI | Built |
| Server-side history, blame & search | Built, speed gates passed |
| Verification & review | **~3,540 tests green** (~970 server tests on PG + YugabyteDB, ~2,570 client/engine); 8 codebase review passes (~75 bugs found & mostly fixed in [docs/BUGS.md](docs/BUGS.md)) |

**Next steps:** diagnose the PostgreSQL pull latency anomaly and 3-server landing drop; add CPU-aware backpressure for YugabyteDB; benchmark `> 1 GB` repositories and multi-zone clusters; add macOS sandboxing.

---

## Documentation

- **Start here:** [What Veil is](docs/OVERVIEW.md) · [Permissions & visibility](docs/VISIBILITY.md) · [Scion for developers](docs/design/scion-for-developers.md)
- **User guide:** [Overview](docs/guide/README.md) · [Getting started](docs/guide/getting-started.md) · [Workspaces & agents](docs/guide/workspaces-and-agents.md) · [The Veil server](docs/guide/the-server.md) · [Secrets & visibility](docs/guide/secrets-and-visibility.md) · [Embargoes](docs/guide/embargoes.md) · [Troubleshooting](docs/guide/troubleshooting.md)
- **Reference & internals:** [Command reference](docs/reference/README.md) · [CLI grammar & platform notes](docs/PLATFORM.md) · [Full benchmarks & trade-offs](docs/BENCHMARKS.md) · [Hub design](docs/HUB.md) · [Architecture](docs/ARCHITECTURE.md) · [Formats](docs/FORMAT.md) · [Crypto](docs/CRYPTO.md) · [Cloud deploy kit](docs/DEPLOY.md)

---

## Contact & Credits

Built by **kittu** — reach out on X at [@kittu_gamer](https://x.com/kittu_gamer) or [kittu.krish695@gmail.com](mailto:kittu.krish695@gmail.com). Questions, ideas, and bug reports are welcome.

Thanks to **okpom**, who helped shape the idea for Veil. Veil owes a great deal to **Jujutsu (`jj`)**, whose change/op-log/conflict model it builds on; **Theo (t3.gg)**, whose argument that Git is holding agents back inspired the project; and **Anthropic's public description of Scion**, whose server-centric design Veil follows. None is affiliated with or has endorsed Veil.
