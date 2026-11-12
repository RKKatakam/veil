# Reproducing Veil's multi-machine numbers

This is for someone who has only the public repository
(`https://github.com/RKKatakam/veil`) and wants to check the numbers Veil
publishes about running across machines, or measure their own. It needs
nothing from the Veil project: a Linux or macOS machine with Docker for the
free rehearsal, and a DigitalOcean account for the paid run.

What the test shows (the owner's goals, 2026-11-12): that Veil **scales on
a realistic agent workload across machines**, with many agents each on a
branch of their own landing into `main`, and that throughput rises with
servers. Per-operation latency across machines may be worse than on one
machine; that is accepted. Every number in the table at the end comes from
a command in this document, and every result directory records what made it.

The runbook behind this page, with the reasons for each choice, is
`docs/DEPLOY.md`; the kit is `deploy/` (`deploy/README.md`).

## 1. Prerequisites

| | For | Check |
|---|---|---|
| Docker 24+ with Compose v2 | the image build, the rehearsal, shipping images to the machines | `docker compose version` |
| 12 GB of free memory, 40 GB of disk, 8 or more cores | the rehearsal (every container has a memory limit; they add up to 11.5 GB) | `free -g`, `df -h` |
| `bash`, `curl`, `openssl`, `python3`, `bc` | the scripts, the certificates, the estimate, the tables | |
| `doctl` 1.100+, `ssh`, `scp`, `zstd` | the paid run only | `doctl version` |
| `awscli` (optional) | the paid run's teardown empties the Spaces bucket with it; without it you delete the bucket in the control panel | `aws --version` |

For the paid run, at DigitalOcean: an account with a payment method; a
personal access token with read and write scope (API → Tokens); a Spaces
key pair (API → Spaces Keys); a **droplet limit of at least 9** (the full
topology has 9 droplets; new accounts often have 3 to 5: ask for more under
Account); your public IPv4 address (`curl -4 -s https://ifconfig.me`).

## 2. Check out the commit

```sh
git clone https://github.com/RKKatakam/veil && cd veil
git checkout COMMIT        # the `commit=` line of the run.txt beside the numbers you are checking
bash deploy/do/test/test.sh   # the kit's own tests; a fake doctl, nothing leaves the machine; ends "all green"
```

## 3. The free rehearsal (about 30 to 45 minutes, no cost)

The paid topology on one machine, small: three YugabyteDB nodes, MinIO in
place of DigitalOcean Spaces, two Veil servers on the one database and
bucket, HAProxy in front of them as the one address, one load driver. Every
gate runs briefly (seconds, tens of agents), the failover gate included,
and everything is torn down at the end.

```sh
deploy/compose/rehearsal.sh me                    # builds the images, runs every gate, tears down
SKIP_BUILD=1 TAG=<tag> deploy/compose/rehearsal.sh me      # reuse images built before
GATES="failover scaling" SKIP_BUILD=1 TAG=<tag> deploy/compose/rehearsal.sh me
DB=pg deploy/compose/rehearsal.sh me              # PostgreSQL 17 instead of YugabyteDB
```

The first build of the images takes 10 to 25 minutes (a release build of
Veil in `rust:1.99.1`); later ones reuse Cargo's cache. Results land in
`deploy/compose/results/<stamp>/`, one directory per gate, laid out as the
paid run's (§6). **The rehearsal's numbers measure nothing**: one machine
plays nine, with tens of agents for seconds. It shows that every step of
the paid run works, end to end, before anything is rented.

At the end the script says `nothing of veil-dokit-me remains (containers,
volumes, networks)`; check with `docker ps -a --filter
label=com.docker.compose.project=veil-dokit-me`.

## 4. The paid run, step by step

Every script is a **dry run** without `--approve`: it prints what it would
do and touches nothing. Run each one dry first. Prices are DigitalOcean's
list prices as the kit knows them (`deploy/do/lib.sh`); `deploy/do/estimate.sh
--live --approve` replaces them with the API's (it only reads).

```sh
cp deploy/do/.env.example deploy/do/.env && chmod 600 deploy/do/.env
$EDITOR deploy/do/.env    # token, Spaces keys, a database password, your IPv4, and:
                          #   VEIL_DO_HUBS=3  VEIL_DO_YB_NODES=3   (the full topology)
deploy/do/estimate.sh     # every topology's hourly rate, the planned 8 hours, a day and a month forgotten
```

The full topology (`VEIL_DO_HUBS=3`, `VEIL_DO_YB_NODES=3`, everything else
as in `.env.example`):

| Machine | Size | Runs | USD/hour |
|---|---|---|---:|
| `NAME-hub`, `-hub2`, `-hub3` | `c-16` (16 dedicated vCPUs, 32 GB) | `veil-server`, one per machine, all on the one database and bucket | 3 × 0.500 |
| `NAME-lb` | `c-4` (4 dedicated vCPUs, 8 GB) | HAProxy 3.0, TLS passed through: the one address | 0.125 |
| `NAME-yb1` to `-yb3` | `c-8` (8 dedicated vCPUs, 16 GB) | YugabyteDB 2025.2.8.1, one node each, three copies of every tablet | 3 × 0.250 |
| `NAME-driver1`, `-driver2` | `c-8` | `veil-bench`, the simulated agents | 2 × 0.250 |
| Spaces bucket | | the servers' object store | $5 a month, flat |
| **total** | | | **2.875** |

| Step | Command | Takes | Costs (full topology) |
|---|---|---|---|
| 0. tests and estimate | `bash deploy/do/test/test.sh`; `deploy/do/estimate.sh` | a minute | nothing |
| 1. images | `deploy/docker/build.sh` (prints the TAG) | 10 to 25 min the first time | nothing |
| 2. create | `deploy/do/create.sh`, then `deploy/do/create.sh --approve` | 2 to 5 min | **billing starts**: $2.875 an hour, and the $5 Spaces month once the bucket exists |
| 3. configure | `deploy/do/configure.sh --approve TAG` | 10 to 20 min (images shipped over SSH) | included in the hours |
| 4. the gates | `deploy/do/bench.sh --approve GATE`, one at a time, in the order below | about 3 hours | included |
| 5. logs | `deploy/do/logs.sh --approve` | 5 min | included |
| 6. teardown | `deploy/do/destroy.sh --approve`; then `deploy/do/destroy.sh --check --approve` until it says `nothing left` | 5 min | billing stops |

Planned: 8 hours of machines, **$28.00** with Spaces (`estimate.sh`); a
teardown forgotten for a day costs $74.00, for a month $1,937.00. The
estimate refuses a plan of $100 or more.

The gates, in order (each one line, sizes from `deploy/gates.sh`):

| # | Command | Measures | About |
|---|---|---|---|
| 1 | `deploy/do/bench.sh --approve pull` | pulls a second with 10, 100 and 1,000 agents while `main` moves 20 times a second; statements per warm pull | 3 min |
| 2 | `deploy/do/bench.sh --approve land` | pushes to `main` from 1 and 50 agents in 1, 10 and 100 projects; database commits per landing | 4 min |
| 3 | `deploy/do/bench.sh --approve api` | the same through `POST …/changes` (the server rebases) | 4 min |
| 4 | `deploy/do/bench.sh --approve branches` | the cost curve (1, 10, 100 agents pushing to branches of their own), then **the headline**: 300, 1,000 and 3,000 agents each on its branch, landing it on `main` through the landing service after every 5th push, 5 minutes each | 20 min |
| 5 | `deploy/do/bench.sh --approve landing` | 10,000 agents of 100 people landing into one `main`, 1,000 a second offered: plain, protected (review rules at 0 approvals), and protected with 3 % overlapping and 2 % conflicting changes; 3 and 10 minutes each | 45 min |
| 6 | `deploy/do/bench.sh --approve scaling` | pulls, pushes to one's own branch and landings across 100 projects with 1, 2 and 3 servers running, from both drivers at once: does throughput rise with servers? | 15 min |
| 7 | `deploy/do/bench.sh --approve failover` | 1,000 agents landing 300 a second into one `main`; 45 s in, the server holding `main`'s landing lease is stopped: another takes over, how long landings paused, every change landed exactly once | 6 min |
| 8 | `deploy/do/bench.sh --approve objects` | fresh thin workspaces reading objects through a server and a regional cache the tool starts on `NAME-hub` | 4 min |
| 9 | `deploy/do/bench.sh --approve openscion` | the OpenScion speed gates, Veil against Git on `NAME-hub`, 1,000 and 10,000 files, 5 runs | 15 min |
| 10 | `deploy/do/bench.sh --approve scale` | the 1 GB profile through a server on `NAME-hub`: push, clone, pull, one directory, gc; the server's peak memory | 40 min |

The PR speed gate (100,000 PRs) is a server test (`prs::pr_speed`), not a
benchmark that can run against a deployed server; it is measured locally
(`docs/design/scale/LOAD.md`). The bisect gate has no benchmark yet.

Exact settings: every size above is a variable in `deploy/gates.sh` (for
example `LANDING_AGENTS=10000`, `HEADLINE_AGENTS=300,1000,3000`,
`MERGE_EVERY=5`, `FAILOVER_RATE=300`) and `run.txt` records all of them.
Change one with the environment (`DURATION=60 deploy/do/bench.sh --approve
pull`); then your numbers are not the published ones.

## 5. Versions

| What | Version | Where it is pinned |
|---|---|---|
| Veil (server, `vl`, `veil-bench`) | the commit you checked out | `run.txt`: `commit=` |
| build image | `rust:1.99.1-bookworm` by digest | `deploy/docker/Dockerfile` |
| runtime base | `debian:12.12-slim` by digest | `deploy/docker/Dockerfile` |
| PostgreSQL | `postgres:17-alpine` by digest | `deploy/versions.env` |
| YugabyteDB | `yugabytedb/yugabyte:2025.2.8.1-b8` by digest | `deploy/versions.env` |
| HAProxy | `haproxy:3.0-alpine` (3.0.30) by digest | `deploy/versions.env` |
| MinIO (rehearsal only) | `bitnamilegacy/minio` by digest | `deploy/versions.env` |
| droplets | Ubuntu 24.04 (`ubuntu-24-04-x64`), Docker from Ubuntu | `deploy/do/lib.sh`, `deploy/do/cloud-init/docker.yaml` |

Your images are built from the same commit and the same pinned bases, but
a Rust release build is not bit-for-bit reproducible here, so their ids
differ from the ones a published `images.txt` names. What must match is
the commit.

## 6. Where results land, and how to read them

`deploy/do/bench.sh` writes `deploy/results/NAME/<stamp>-<gate>/` (the
rehearsal: `deploy/compose/results/<stamp>/<gate>/`):

| File | What |
|---|---|
| `run.txt` | the gate, the date, `commit=`, `image_tag=`, the address the agents used, the number of servers, every size setting |
| `topology.env` | the topology from `deploy/do/.env`: names, region, sizes, counts, image references; never a secret (a fixed list of names) |
| `images.txt` | the image ids built here and the ones each machine runs; the pinned third-party digests |
| `commands.txt` | every `veil-bench` command line, and the machine it ran on |
| `<label>.json` | the tool's raw results: one object per curve point under `runs`, with `ops_per_s`, `p50_ms`, `p99_ms`, `errors`, `db_commits_per_op`, `gates_missed`, … |
| `<label>.md` | the same as a table; `<label>.log` the tool's output (`GATE MISSED:` lines name each missed target) |
| `hub<N>-stats.json`, `hub<N>-docker-stats.log` | each server's request-path counters at the end (the landing service's batches, landings and timings among them: the tool fills its own `landing_*` fields only for a server it starts), and its CPU and memory every 5 s |
| `scaling.md` | the scaling table: each curve's throughput with 1, 2 and 3 servers (summed over the drivers), and its ratio to one server's |
| `failover-verdict.md`, `failover-check.txt`, `failover-run.txt`, `failover-after.txt`, `failover.json` | the failover verdict, the database's checks behind it, what the gate did and when |

A gate's command exits non-zero when a run failed or missed one of the
tool's targets; the results are kept either way.

## 7. Teardown, and the check that nothing is left

```sh
deploy/do/destroy.sh --approve           # droplets by tag, firewall, SSH key, tag; empties and deletes the Spaces buckets
deploy/do/destroy.sh --check --approve   # exits 0 and says "nothing left" only when it is so
```

The check counts droplets tagged with the run's name, firewalls and SSH
keys of that name, volumes, snapshots and load balancers whose names start
with it, every reserved IP in the account (an unassigned one bills), and
asks Spaces for each bucket the run could have made. Run it until it
passes; look at Billing the next day. Rotate the token and the Spaces keys
afterwards.

## 8. What we measured

Filled in from the paid run's result directories; each cell names the gate
and the file it comes from. Empty: not run yet.

| Number | Gate | From | Value |
|---|---|---|---|
| headline: pushes/s and merges into `main`/s, 300 agents on branches, merging every 5th push | `branches` | `branches-merge.json`, run `clients=300`: `ops_per_s`, `p50_ms`, `p99_ms`; merges/s = `branch_merges` / `seconds` | |
| the same, 1,000 agents | `branches` | `branches-merge.json`, `clients=1000` | |
| the same, 3,000 agents | `branches` | `branches-merge.json`, `clients=3000` | |
| landings/s into one `main`, 10,000 agents of 100 people, plain, 3 min / 10 min | `landing` | `landing-plain-180s.json`, `landing-plain-600s.json`: `ops_per_s`, `p50_ms`, `p99_ms` | |
| the same, protected `main` | `landing` | `landing-protected-180s.json`, `landing-protected-600s.json` | |
| the same, protected, with the mix | `landing` | `landing-mix-180s.json`, `landing-mix-600s.json` | |
| database commits per landing (PostgreSQL only: the tool counts PostgreSQL transaction ids, and reports 0 on YugabyteDB) | `landing` | `landing-*.json`: `db_commits_per_op` | |
| pulls/s with 1, 2, 3 servers | `scaling` | `scaling.md` (from `scaling-<N>servers-pull@<driver>.json`) | |
| pushes to one's own branch/s with 1, 2, 3 servers | `scaling` | `scaling.md` (`scaling-<N>servers-branches@<driver>.json`) | |
| landings across 100 projects/s with 1, 2, 3 servers | `scaling` | `scaling.md` (`scaling-<N>servers-landing@<driver>.json`) | |
| failover: another server took the lease | `failover` | `failover-verdict.md`, row "lease holder before / after" | |
| failover: longest pause in landings | `failover` | `failover-verdict.md` (`failover-check.txt`: `longest_gap_after_stop_ms`) | |
| failover: changes lost / landed twice | `failover` | `failover-verdict.md` (`failover-check.txt`: `unfinished`, `recorded_not_on_main`, `change_twice_on_main`, `main_without_ticket`) | |
| pulls/s, 10 / 100 / 1,000 agents; statements per warm pull | `pull` | `pull.json`: `ops_per_s`, `db_per_op` | |
| landings/s into `main`, 1 and 50 agents, 1 / 10 / 100 projects | `land` | `land.json` | |
| API commits/s, the same points | `api` | `api.json` | |
| pushes/s to one's own branch, 1 / 10 / 100 agents; commits and storage writes per push | `branches` | `branches.json`: `ops_per_s`, `db_commits_per_op`, `storage_writes_per_op` | |
| object reads from the regional cache's store; the cache's peak memory | `objects` | `objects.json` | |
| OpenScion: import, clone, commit one file, clone one directory, 1,000 and 10,000 files, against Git | `openscion` | `openscion.md` | |
| 1 GB profile: push, clone, pull; the server's peak memory | `scale` | `scale-1g.md` | |
